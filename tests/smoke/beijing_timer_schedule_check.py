"""Runtime proof for the Beijing-time key-refresh schedule.

Runs the real fallback blocks extracted from install-service.sh (bash) and
package.py's DEB_POSTINST (dash, i.e. /bin/sh) against a stubbed `date +%z`,
then checks every emitted local time maps back to Beijing 00/06/12/18 exactly.

This is the anti-falsification half: a schedule that merely "looks" right, or a
shell block that only parses under bash, must fail here.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PY = sys.executable


def extract(path, start, end, dedent_to=""):
    text = (ROOT / path).read_text(encoding="utf-8")
    i = text.index(start)
    j = text.index(end, i)
    return text[i:j]


def dedent(block):
    lines = [ln for ln in block.splitlines()]
    pad = min((len(ln) - len(ln.lstrip()) for ln in lines if ln.strip()), default=0)
    return "\n".join(ln[pad:] if ln.strip() else "" for ln in lines)


# Beijing 00:00/06:00/12:00/18:00 expressed in UTC.
BEIJING_INSTANTS_UTC = {0, 360, 720, 1080}


def expected_local_hours(offset_min):
    out = set()
    for b in BEIJING_INSTANTS_UTC:
        local = (b - 480 + offset_min) % 1440
        out.add(local)
    return out


def to_posix(path):
    """Path as the target shell sees it. On POSIX there is nothing to do --
    and calling cygpath there would crash (ubuntu runners have no such tool).
    On Windows a native path (backslashes, drive letter) is not a valid PATH
    entry inside sh, so convert via cygpath; if even that is missing, apply
    the MSYS drive mapping by hand ("C:\\x" -> "/c/x"). A naive "C:/x"
    spelling is NOT enough: with a Windows-format inherited PATH the MSYS
    shells treat "C:/..." PATH entries as relative garbage."""
    if os.name != "nt":
        return str(path)
    if shutil.which("cygpath"):
        r = subprocess.run(
            ["cygpath", "-u", str(path)], capture_output=True, text=True
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    m = re.match(r"^([A-Za-z]):[/\\](.*)$", str(path))
    if m:
        return "/{}/{}".format(m.group(1).lower(), m.group(2).replace("\\", "/"))
    return str(path).replace("\\", "/")


def resolve_shell(name):
    """Absolute path of `name`, refusing the WSL stub on Windows.

    System32\\bash.exe launches WSL, whose /tmp is a different filesystem from
    the MSYS /tmp cygpath maps our probe into -- CI evidence: every bash case
    exited 1 silently on the windows runner while every dash case (resolved to
    Git-for-Windows' usr/bin/dash.exe) passed. When the generic lookup lands in
    System32 (or misses), derive the MSYS shell from git.exe's own location,
    which covers both the runner's Program Files layout and PortableGit.
    Returns None when nothing usable exists.
    """
    def usable(p):
        return bool(p) and "system32" not in p.lower().replace("\\", "/")

    p = shutil.which(name)
    if usable(p):
        return p

    candidates = []
    git = shutil.which("git")
    if git:
        # git.exe may sit in <root>/cmd or <root>/bin (old layout); the MSYS
        # shells live in <root>/usr/bin and <root>/bin.
        root = os.path.dirname(os.path.dirname(os.path.abspath(git)))
        for sub in ("usr", ""):
            candidates.append(os.path.join(root, sub, "bin", name + ".exe"))
    candidates += [
        rf"C:\Program Files\Git\bin\{name}.exe",
        rf"C:\Program Files\Git\usr\bin\{name}.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def run_block(shell, block, offset, var="sched", shell_path=None):
    """Execute the fallback block with a stubbed `date +%z`."""
    tmp = Path(tempfile.mkdtemp())
    bindir = tmp / "bin"
    bindir.mkdir()
    # Stub only the offset query; every other date call is irrelevant here.
    # NB: the stub must echo the offset with `echo`, never `printf '%z'` --
    # "%z" is not a valid printf format character, so a printf-based stub
    # fails outright and every case would silently use the host's real offset.
    date_stub = (
        "#!/bin/sh\n"
        'if [ "$1" = "+%z" ]; then echo "' + offset + '"; exit 0; fi\n'
        'exec /usr/bin/date "$@"\n'
    )
    (bindir / "date").write_bytes(date_stub.encode("utf-8"))
    (bindir / "systemd-analyze").write_bytes(b"#!/bin/sh\nexit 1\n")  # force fallback
    for name in ("date", "systemd-analyze"):
        (bindir / name).chmod(0o755)
    script = tmp / "probe.sh"
    # The stub dir must be spelled the way the shell sees it (see to_posix).
    posix_bindir = to_posix(bindir)
    # NB: write bytes, not write_text. On Windows write_text translates "\n" to
    # CRLF, and dash rejects a CRLF file outright (`esac\r` is not a token) --
    # bash tolerates it, so a bash-only check would hide the whole failure.
    # NB: /usr/bin:/bin is explicit; the inherited $PATH is only a tail. When
    # the parent env is a Windows shell, the inherited PATH is in Windows
    # format ("C:\...;...") and a bare PATH=stub:$PATH left EVERY external
    # tool (date, tr, sort, cut, wc) unresolvable, so the block silently
    # degraded to "*-*-* :00" (CI windows runner and local PowerShell both
    # proved it). The stub dir stays first so date/systemd-analyze stubs win.
    script.write_bytes(
        (
            "#!/bin/sh\nPATH=%s:/usr/bin:/bin:$PATH\n%s=\n%s\n"
            "printf 'SCHED=%%s\\n' \"$%s\"\n"
            % (posix_bindir, var, block, var)
        ).encode("utf-8")
    )
    env = dict(os.environ)
    posix_script = to_posix(script)
    # NB: decode explicitly as UTF-8 with replacement. The default (locale)
    # decoding crashes the reader thread when bash prints a localized message
    # in e.g. GBK, which truncates stdout and corrupts the SCHED line.
    proc = subprocess.run(
        [shell_path or shell, posix_script], capture_output=True, env=env,
        encoding="utf-8", errors="replace",
    )
    if os.environ.get("KCP_TIMER_DEBUG"):
        keep = Path("D:/work/kcp-proxy-cpp/.workbuddy/tmp") / ("probe_%s.sh" % shell)
        keep.parent.mkdir(parents=True, exist_ok=True)
        keep.write_text(script.read_text(encoding="utf-8"), encoding="utf-8")
        sys.stderr.write("kept %s\n" % keep)
    shutil.rmtree(tmp, ignore_errors=True)
    return proc

def parse_sched(stdout):
    m = re.search(r"SCHED=(.*)$", stdout, re.M)
    if not m:
        return None
    expr = m.group(1).strip()
    mm = re.match(r"\*-\*-\* (\S+)", expr)
    return mm.group(1) if mm else None


def parse_local_minutes(field):
    """'04,10,16,22:00:00' (hour list) or '21:30:00' (single time)."""
    parts = field.split(":")
    if len(parts) == 1:
        # systemd's shortest form: bare hours, e.g. "04,10,16,22".
        return {int(h) * 60 for h in parts[0].split(",")}
    mi = int(parts[1])
    return {int(h) * 60 + mi for h in parts[0].split(",")}


CASES = [
    ("+0000", 0),      # UTC host
    ("+0800", 480),    # Beijing host -- must equal the old local 0/6/12/18
    ("-0500", -300),   # US Eastern
    ("-0800", -480),   # US Pacific
    ("+1400", 840),    # NZ
    ("-1100", -660),   # Pacific island
    # Sub-hour offsets take the single-tick branch. That tick must be Beijing
    # midnight's conversion -- the earliest wall-clock time of the four is a
    # different instant (+0545: earliest local 03:45 is Beijing 06:00), and
    # scheduling it leaves the key stale for hours after every date change.
    ("+0545", 345),    # Nepal
    ("-0330", -210),   # Newfoundland
]


def expected_local_minutes(offset_min):
    """Whole-hour hosts keep all four daily ticks; a sub-hour host's single
    OnCalendar entry must be Beijing midnight's own conversion (b=0)."""
    if offset_min % 60 == 0:
        return expected_local_hours(offset_min)
    return {(0 - 480 + offset_min) % 1440}


def extract_rendered_postinst():
    """The postinst is an f-string; its {{ }} escapes must be rendered first,
    otherwise the probe shell would see literal double braces."""
    sys.path.insert(0, str(ROOT / "scripts" / "package"))
    import package  # noqa: E402

    text = package.DEB_POSTINST
    i = text.index("            off=$(date +%z)")
    j = text.index('            sed -i "s|^OnCalendar=', i)
    return dedent(text[i:j])


def main():
    failures = []

    blocks = [
        ("install-service.sh", "bash", "TIMER_SCHEDULE", dedent(extract(
            "scripts/deploy/install-service.sh",
            '    _off=$(date +%z)',
            '    TIMER_TZ_NOTE="host-local fallback'))),
        ("DEB_POSTINST (dash)", "dash", "sched", extract_rendered_postinst()),
    ]

    # Resolve each shell once up front and fail loudly with the resolution
    # result, so a runner without bash/dash reports *why* instead of crashing
    # or silently degrading.
    resolved = {}
    for label, shell, _var, _blk in blocks:
        resolved[shell] = resolve_shell(shell)
        if resolved[shell] is None:
            if os.name == "nt" and shell == "dash":
                # dash is a Debian/MSYS tool, not a Windows one; the dash
                # compatibility of the postinst is proven on the linux job.
                print(f"  SKIP {label}: no dash.exe on this Windows host "
                      "(verified on the linux CI job)")
                blocks = [b for b in blocks if b[1] != "dash"]
            else:
                print(f"FAIL: required shell {shell!r} not found on this host")
                return 1
        else:
            print(f"  shell {shell}: {resolved[shell]}")

    for label, shell, var, block in blocks:
        for off, off_min in CASES:
            proc = run_block(shell, block, off, var, shell_path=resolved[shell])
            if proc.returncode != 0:
                failures.append(
                    f"{label} offset {off}: exit {proc.returncode} "
                    f"shell={resolved[shell]}: {proc.stderr.strip()[:200]}"
                )
                continue
            sched = parse_sched(proc.stdout)
            if sched is None:
                failures.append(f"{label} offset {off}: no SCHED emitted ({proc.stdout!r})")
                continue
            try:
                got = parse_local_minutes(sched)
            except (ValueError, IndexError):
                failures.append(f"{label} offset {off}: unparseable schedule {sched!r} "
                                f"(stdout {proc.stdout!r})")
                continue
            want = expected_local_minutes(off_min)
            if got != want:
                failures.append(
                    f"{label} offset {off}: schedule {sched!r} -> local minutes {sorted(got)}, "
                    f"want {sorted(want)}"
                )
            else:
                print(f"  ok  {label:20s} host {off}  ->  {sched}")

    # The +0800 case must reproduce exactly the pre-change behaviour (0/6/12/18
    # Beijing local), i.e. on a Beijing host the UTC schedule is equivalent.
    _label, _shell, _var, _blk = blocks[0]
    proc = run_block(_shell, _blk, "+0800", _var, shell_path=resolved[_shell])
    if parse_sched(proc.stdout) != "00,06,12,18:00:00":
        failures.append(
            f"Beijing host should keep 00,06,12,18 local, got {parse_sched(proc.stdout)!r}"
        )

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nall Beijing-time schedule conversions verified at runtime")
    return 0


if __name__ == "__main__":
    sys.exit(main())
