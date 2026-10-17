"""Runtime proof for the Beijing-time key-refresh schedule.

Runs the real fallback blocks extracted from install-service.sh (bash) and
package.py's DEB_POSTINST (dash, i.e. /bin/sh) against a stubbed `date +%z`,
then checks every emitted local time maps back to Beijing 00/06/12/18 exactly.

This is the anti-falsification half: a schedule that merely "looks" right, or a
shell block that only parses under bash, must fail here.
"""
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


def run_block(shell, block, offset, var="sched"):
    """Execute the fallback block with a stubbed `date +%z`."""
    import os

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
    # The stub dir must be spelled the way the shell sees it: a native Windows
    # path (backslashes, drive letter) is not a valid PATH entry inside sh, so
    # the stubs would silently never run and every case would "pass" with the
    # host's real offset.
    posix_bindir = subprocess.run(
        ["cygpath", "-u", str(bindir)], capture_output=True, text=True
    ).stdout.strip() or str(bindir).replace("\\", "/")
    # NB: write bytes, not write_text. On Windows write_text translates "\n" to
    # CRLF, and dash rejects a CRLF file outright (`esac\r` is not a token) --
    # bash tolerates it, so a bash-only check would hide the whole failure.
    script.write_bytes(
        (
            "#!/bin/sh\nPATH=%s:$PATH\n%s=\n%s\nprintf 'SCHED=%%s\\n' \"$%s\"\n"
            % (posix_bindir, var, block, var)
        ).encode("utf-8")
    )
    env = dict(os.environ)
    posix_script = subprocess.run(
        ["cygpath", "-u", str(script)], capture_output=True, text=True
    ).stdout.strip() or str(script).replace("\\", "/")
    proc = subprocess.run(
        [shell, posix_script], capture_output=True, text=True, env=env
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
]


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

    for label, shell, var, block in blocks:
        for off, off_min in CASES:
            proc = run_block(shell, block, off, var)
            if proc.returncode != 0:
                failures.append(
                    f"{label} offset {off}: exit {proc.returncode}: {proc.stderr.strip()[:200]}"
                )
                continue
            sched = parse_sched(proc.stdout)
            if sched is None:
                failures.append(f"{label} offset {off}: no SCHED emitted ({proc.stdout!r})")
                continue
            got = parse_local_minutes(sched)
            want = expected_local_hours(off_min)
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
    proc = run_block(_shell, _blk, "+0800", _var)
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
