#!/usr/bin/env python3
"""Static smoke tests for packaging / deployment / release invariants.

Standard library only and no build step: every check reads the tracked sources,
so the suite finishes in well under a second and catches the things a compile
and a unit test cannot see -- file layout, shell-injection guards, secret
hygiene, and drift between the files that are required to agree (vcpkg pins,
release versions, the suffix rule, the GUI/client key handoff).

Run directly (this is exactly what CI does):

    python3 tests/smoke/smoke_test.py
"""
from __future__ import annotations

from pathlib import Path
import json
import re
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    """Like assert, but the message survives -O and always reaches the report."""
    if not condition:
        raise AssertionError(message)


# --------------------------------------------------------------------------- #
# packaging
# --------------------------------------------------------------------------- #
def test_packaging_script():
    text = read("scripts/package/package.py")

    # Self-locating: the repo root is derived from __file__, never from the
    # caller's cwd, so the packager works when invoked from any directory.
    require("Path(__file__).resolve().parents[2]" in text,
            "package.py must locate the repo root from __file__, not from cwd")

    # Archive permissions come from an explicit table, never from stat():
    # Windows has no Unix mode bits, so stat-derived modes would silently ship
    # non-executable binaries. The config file holds the key suffix, so it is
    # the one member that must be installed 0600.
    require("DEB_MODES" in text and "MODE_SECRET = 0o600" in text,
            "package.py must declare archive permissions explicitly")
    require("Never derived from the build host" in text,
            "package.py must document that archive modes are never stat()-derived")
    require('"./etc/kcp-proxy/server.env": MODE_SECRET' in text,
            "the .deb config file (holds the key suffix) must be installed 0600")

    # Members are written one by one from explicit TarInfo entries, so a
    # symlink or an absolute path can never be swept in implicitly.
    require("tar.addfile(" in text,
            "package.py must add explicit members to the tarball")
    require("tar.add(" not in text,
            "package.py must not use recursive tar.add(), which follows symlinks")

    # The version is read from CMakeLists.txt: one source of truth.
    require("CMAKE_VERSION_RE" in text and "CMakeLists.txt" in text,
            "package.py must derive the version from CMakeLists.txt")

    # build_deb() refuses to run without the systemd templates it ships.
    for template in ("kcp-proxy-server-key-refresh.service",
                     "kcp-proxy-server-key-refresh.timer"):
        require((ROOT / "scripts" / "templates" / template).is_file(),
                f"missing systemd template: scripts/templates/{template}")

    # The standalone archive must ship the launchers CMakeLists installs and the
    # README documents; without them a user who unpacks a release has no start
    # script (this is exactly how the references drifted before).
    for launcher in ("start.sh", "start.bat"):
        require(launcher in text,
                f"package.py must ship scripts/runtime/{launcher} in the CLI archive")
        require((ROOT / "scripts" / "runtime" / launcher).is_file(),
                f"missing runtime launcher: scripts/runtime/{launcher}")


# --------------------------------------------------------------------------- #
# secrets
# --------------------------------------------------------------------------- #
def test_no_committed_secrets():
    common = read("scripts/runtime/common.sh")

    # A production key used to be checked in here as the default suffix.
    require("Kcp$Pr0xy!2024#Sec" not in common,
            "scripts/runtime/common.sh must not carry the legacy built-in key")
    match = re.search(r'^DEFAULT_SUFFIX="([^"]*)"', common, re.MULTILINE)
    require(match is not None, 'common.sh must define DEFAULT_SUFFIX=""')
    require(match.group(1) == "",
            "DEFAULT_SUFFIX must be empty: no default secret ships in the repo")

    require("Kcp$Pr0xy!2024#Sec" not in read("scripts/deploy/deploy.py"),
            "deploy.py must not carry a built-in key")

    # The generated server wrapper must log only the key date and the suffix
    # length -- never the assembled key, which is the SOCKS5/KCP credential.
    package = read("scripts/package/package.py")
    require("key_date=${DATE_BEIJING}  suffix_len=${#SUFFIX}" in package,
            "the server wrapper must log only the key date and suffix length")


# --------------------------------------------------------------------------- #
# deployment safety
# --------------------------------------------------------------------------- #
def test_deploy_safety():
    deploy = read("scripts/deploy/deploy.py")

    # Remote staging must be unpredictable: a fixed path under a world-writable
    # directory lets a local user pre-create it and win the race (symlink
    # attack). mktemp allocates the name atomically.
    require("mktemp -d /var/tmp/kcp-proxy-deploy.XXXXXX" in deploy,
            "deploy.py must stage under a randomised mktemp directory")
    require('"/tmp/kcp-proxy-deploy"' not in deploy,
            "deploy.py must not use a predictable /tmp staging path")
    require("secrets.token_hex" in deploy,
            "the uploaded archive name must be randomised")
    require("chmod 700" in deploy,
            "the remote staging directory must not be world-readable")

    # Everything interpolated into the remote shell command must be quoted.
    require(deploy.count("shlex.quote") >= 3,
            "deploy.py must shlex.quote every value interpolated into the remote command")

    # The archive is validated before it is trusted.
    require("def validate_tar_members" in deploy,
            "deploy.py must validate archive members")
    for guard in ("is_absolute()", '".." in name.parts', "issym()"):
        require(guard in deploy,
                f"deploy.py archive validation must cover {guard}")


# --------------------------------------------------------------------------- #
# the GUI -> client key handoff
# --------------------------------------------------------------------------- #
def test_gui_never_puts_the_key_on_the_command_line():
    main = read("gui/electron/main.js")

    # The command line of a process is visible to every local user (Task
    # Manager / wmic); the environment is readable only by the same user. The
    # key is a credential, so it must travel through the environment.
    require("args.join(' ')" not in main,
            "the GUI must spawn with an argv array, never a shell string")
    require("'-k'" not in main and "'--key'" not in main,
            "the GUI must not put the key on the client's command line")

    # The handoff itself lives in the pure helper (main.js only mentions the
    # variable in a comment), so assert on the file that actually sets it --
    # checking main.js used to pass even with the real assignment deleted.
    utils = read("gui/electron/utils.js")
    require("KCP_PROXY_KEY" in utils and "buildClientEnv" in utils,
            "utils.js must hand the key to the client through the environment")
    require(re.search(r"KCP_PROXY_KEY:\s*key", utils) is not None,
            "buildClientEnv must assign the key to KCP_PROXY_KEY")

    # ...and the client must actually read that variable, or the GUI is broken.
    require('get_env("KCP_PROXY_KEY")' in read("src/main_client.cpp"),
            "the client must read KCP_PROXY_KEY from the environment")


# --------------------------------------------------------------------------- #
# the GUI's client-binary search path
# --------------------------------------------------------------------------- #
def test_gui_finds_the_dev_build():
    main = read("gui/electron/main.js")

    # Regression guard: the dev-mode candidate used '../../..' from
    # gui/electron, which resolves to the PARENT of the repository, so a
    # machine with only a CMake build tree got "client not found". From
    # gui/electron the repo root is two levels up.
    newline = chr(10)
    start = main.index("function getClientPath")
    block = main[start:main.index(newline + "}", start)]
    require("'../../../build" not in block and '"../../../build' not in block,
            "getClientPath must not reach above the repository root for build/Release")
    require("'../../build/Release'" in block,
            "getClientPath must look in <repo>/build/Release")


def test_gui_maps_darwin_to_the_macos_bin_dir():
    # main.js maps process.platform 'darwin' onto the bin/macos directory that
    # build.sh produces; the runtime test helper must agree or every case
    # silently self-skips on macOS.
    test_src = read("gui/electron/test/launch-contract.test.js")
    require("'darwin' ? 'macos'" in test_src,
            "launch-contract.test.js must map darwin onto the macos bin dir")


# --------------------------------------------------------------------------- #
# deploy tooling (the one path that is fully local and was never executed)
# --------------------------------------------------------------------------- #
def test_deploy_dry_run():
    # --dry-run is the only branch of deploy.py that touches neither SSH nor
    # the network, which is exactly why it was never run by CI: the assertions
    # above only grep the file's text. --uninstall narrows the payload to
    # tracked scripts, so this executes the real packaging + archive-validation
    # code on every platform (no bin/linux binary required).
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "deploy" / "deploy.py"),
         "root@localhost", "--uninstall", "--dry-run"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=120)
    require(result.returncode == 0,
            f"deploy.py --dry-run failed ({result.returncode}): {result.stderr.strip()}")
    require("uninstall-service.sh" in result.stdout,
            "the dry-run package must contain uninstall-service.sh")
    require("common.sh" in result.stdout,
            "the dry-run package must contain common.sh")
    require("SHA256:" in result.stdout,
            "the dry-run must report the package checksum")


# --------------------------------------------------------------------------- #
# systemd service install / uninstall
# --------------------------------------------------------------------------- #
def test_service_scripts():
    install = read("scripts/deploy/install-service.sh")

    require('dirname "${BASH_SOURCE[0]}"' in install,
            "install-service.sh must locate itself from BASH_SOURCE, not cwd")

    # The unit hardens the filesystem (ProtectSystem=strict), so the single
    # writable path is granted explicitly and LOG_FILE must stay inside it.
    require("ReadWritePaths=-$LOG_DIR" in install,
            "the unit must grant write access to the log directory")
    require("/var/log/kcp-proxy/*)" in install,
            "install-service.sh must confine LOG_FILE to the log directory")

    # The daily key is rotated by a systemd timer, and an unarmed timer freezes
    # the key silently (clients then fail DECRYPT_FAILED), so the installer has
    # to verify the timer actually scheduled a next run.
    require("kcp-proxy-server-key-refresh.timer" in install,
            "install-service.sh must install the key-refresh timer")
    require("NextElapseUSecRealtime" in install,
            "install-service.sh must verify the timer has a next elapse")
    require("OnCalendar=" in install,
            "the refresh timer must use a calendar schedule, not OnBootSec")

    uninstall = read("scripts/deploy/uninstall-service.sh")
    require("--purge" in uninstall, "uninstall-service.sh must support --purge")
    require('if [ "$PURGE" -eq 1 ]; then' in uninstall
            and 'rm -rf "$ENV_DIR"' in uninstall,
            "uninstall-service.sh must remove configuration only under --purge")
    require('rm -rf "$INSTALL_DIR"' in uninstall,
            "uninstall-service.sh must always remove the installed binaries")


# --------------------------------------------------------------------------- #
# pins and versions that must agree across files
# --------------------------------------------------------------------------- #
def test_udp_buffer_ceiling_agrees():
    # The server asks the kernel for 4 MiB UDP socket buffers (config.hpp), but
    # the kernel silently clamps that request to net.core.rmem_max / wmem_max
    # without reporting an error. That was the 2026-09-23 incident: 4 MiB
    # requested, 208 KiB granted, burst datagrams dropped by the kernel and
    # misread by KCP as network loss. Raising the ceiling is the deploy scripts'
    # job, and the number has to agree in every place that names it or the fix
    # is cosmetic. Same drift-guard idea as test_vcpkg_pins_agree.
    config = read("src/kcp_proxy/config.hpp")
    common = read("scripts/runtime/common.sh")

    def literal_int(source: str, pattern: str, label: str) -> int:
        match = re.search(pattern, source, re.MULTILINE)
        require(match is not None, f"{label} not found")
        expr = match.group(1).strip()
        # Only ever a literal arithmetic expression from our own source; refuse
        # anything else rather than eval() it.
        require(re.fullmatch(r"[0-9][0-9 *+()]*", expr) is not None,
                f"{label} must be a plain integer expression, got {expr!r}")
        return int(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 - digits and operators only

    rcv = literal_int(config, r"constexpr int UDP_SO_RCVBUF_BYTES\s*=\s*([0-9 *+()]+);",
                      "config.hpp UDP_SO_RCVBUF_BYTES")
    snd = literal_int(config, r"constexpr int UDP_SO_SNDBUF_BYTES\s*=\s*([0-9 *+()]+);",
                      "config.hpp UDP_SO_SNDBUF_BYTES")
    rmem = literal_int(common, r"^UDP_RMEM_MAX=([0-9]+)$", "common.sh UDP_RMEM_MAX")
    wmem = literal_int(common, r"^UDP_WMEM_MAX=([0-9]+)$", "common.sh UDP_WMEM_MAX")

    require(rmem == rcv,
            f"common.sh UDP_RMEM_MAX={rmem} must equal config.hpp "
            f"UDP_SO_RCVBUF_BYTES={rcv} (the ceiling must match what the server asks for)")
    require(wmem == snd,
            f"common.sh UDP_WMEM_MAX={wmem} must equal config.hpp "
            f"UDP_SO_SNDBUF_BYTES={snd} (the ceiling must match what the server asks for)")

    match = re.search(r'^SYSCTL_CONF="([^"]+)"', common, re.MULTILINE)
    require(match is not None, 'common.sh must define SYSCTL_CONF="<path>"')
    conf = match.group(1)
    require(conf.startswith("/etc/sysctl.d/") and conf.endswith(".conf"),
            f"SYSCTL_CONF must be a /etc/sysctl.d/*.conf drop-in, got {conf}")

    install = read("scripts/deploy/install-service.sh")
    uninstall = read("scripts/deploy/uninstall-service.sh")
    package = read("scripts/package/package.py")

    # package.py does not source common.sh, so it carries its own copy of the
    # path and the constants -- and they have to be the same ones.
    for name, text in (("install-service.sh", install),
                       ("uninstall-service.sh", uninstall),
                       ("package.py", package)):
        require(conf in text or "{SYSCTL_CONF}" in text,
                f"{name} must reference the sysctl drop-in {conf}")
    for const, want in (("UDP_RMEM_MAX", rmem), ("UDP_WMEM_MAX", wmem)):
        m = re.search(rf"^{const} = ([0-9]+)$", package, re.MULTILINE)
        require(m is not None, f"package.py must define {const}")
        require(int(m.group(1)) == want,
                f"package.py {const}={m.group(1)} must equal common.sh's {want}")

    # Only-raise, never-lower. Both writers must gate each key on the host's
    # current value being lower: an unconditional write would cap a host an
    # operator had deliberately tuned above 4 MiB, which is worse than leaving
    # it alone.
    for name, text in (("install-service.sh", install), ("package.py", package)):
        for key in ("rmem", "wmem"):
            require(re.search(rf'\[ "\$cur_{key}" -lt ', text) is not None,
                    f"{name} must only raise {key}_max when the host value is lower")

    # The ceiling has to be in place BEFORE the service starts: the server reads
    # the clamp once, at startup, so applying it afterwards leaves the running
    # process holding the small buffer until someone restarts it by hand.
    require(install.index("\napply_udp_buffer_ceiling\n")
            < install.index('systemctl restart "$SERVICE_NAME"'),
            "install-service.sh must apply the ceiling before restarting the service")
    require(package.index("sysctl -n net.core.rmem_max")
            < package.index('systemctl restart "$SERVICE_NAME"'),
            "the deb postinst must apply the ceiling before restarting the service")

    # Both removal paths must clean it up: the drop-in is written by the
    # installer, so dpkg does not track it and would otherwise leave a sysctl
    # file capping rmem_max for the whole host after an uninstall.
    require('rm -f "$SYSCTL_CONF"' in uninstall,
            "uninstall-service.sh must remove the sysctl drop-in")
    require("rm -f {SYSCTL_CONF}" in package,
            "the deb postrm must remove the sysctl drop-in")
    # Removing a drop-in does not lower a value that is already live, so the
    # uninstaller has to say so instead of implying a clean rollback.
    require("until the next reboot" in uninstall,
            "uninstall-service.sh must warn that the raised ceiling survives until reboot")


def test_vcpkg_pins_agree():
    build = read("build.sh")
    match = re.search(r'VCPKG_COMMIT="([0-9a-f]{40})"', build)
    require(match is not None,
            'build.sh must pin a vcpkg commit (VCPKG_COMMIT="<40-hex>")')
    pinned = match.group(1)

    # vcpkg.json's builtin-baseline names the upstream state the manifest
    # resolves against; a mismatch builds against a different vcpkg tree.
    require(json.loads(read("vcpkg.json"))["builtin-baseline"] == pinned,
            "vcpkg.json builtin-baseline must match build.sh's VCPKG_COMMIT")

    # CI pins vcpkg itself -- drift here means the release artifacts are built
    # against a vcpkg no local build ever used.
    ci_pins = re.findall(r"vcpkgGitCommitId:\s*([0-9a-f]{40})",
                         read(".github/workflows/ci.yml"))
    require(ci_pins, "ci.yml must pin vcpkgGitCommitId")
    for pin in ci_pins:
        require(pin == pinned,
                f"ci.yml pins vcpkg {pin} but build.sh pins {pinned}")

    # CMakePresets.json is parsed by CMake directly; invalid JSON fails late.
    json.loads(read("CMakePresets.json"))


def test_versions_agree():
    match = re.search(r"project\(\s*kcp_proxy\s+VERSION\s+(\d+\.\d+\.\d+)",
                      read("CMakeLists.txt"))
    require(match is not None,
            "CMakeLists.txt must declare project(kcp_proxy VERSION x.y.z)")
    version = match.group(1)

    # The release version is duplicated in the manifest and the GUI package. A
    # mismatch ships binaries whose reported version (generated from
    # CMakeLists.txt) differs from the archive name the packager derives.
    require(json.loads(read("vcpkg.json"))["version"] == version,
            "vcpkg.json version must match CMakeLists.txt")
    require(json.loads(read("gui/electron/package.json"))["version"] == version,
            "gui/electron/package.json version must match CMakeLists.txt")


def test_suffix_validation_agrees():
    """The shell and Python halves of the suffix rule must not drift: the
    installer validates it on the server, deploy.py validates it before upload."""
    shell = re.search(r"=~ \^(\[[^\]]+\]\{\d+,\d+\})\$",
                      read("scripts/runtime/common.sh"))
    require(shell is not None, "common.sh must validate the suffix with a regex")
    python = re.search(r're\.fullmatch\(r"(\[[^\]]+\]\{\d+,\d+\})"',
                       read("scripts/deploy/deploy.py"))
    require(python is not None, "deploy.py must validate the suffix with a regex")

    require(shell.group(1) == python.group(1),
            "suffix rule drift: common.sh has "
            f"{shell.group(1)!r}, deploy.py has {python.group(1)!r}")

    pattern = re.compile("^" + python.group(1) + "$")
    for value in ("abcdefgh", "abc_1234", "release-2026", "A" * 128):
        require(pattern.fullmatch(value) is not None,
                f"suffix {value!r} must be accepted")
    for value in ("", "short", "abc def", "abc=1234", "abc\n1234", "A" * 129):
        require(pattern.fullmatch(value) is None,
                f"suffix {value!r} must be rejected")


# --------------------------------------------------------------------------- #
# CI wiring
# --------------------------------------------------------------------------- #
def test_ci_runs_this_suite_and_the_whitespace_check():
    """CI used to run only ctest, so a whitespace error or a packaging
    regression could merge green. Pin the steps that close that gap."""
    ci = read(".github/workflows/ci.yml")
    require("tests/smoke/smoke_test.py" in ci,
            "CI must run tests/smoke/smoke_test.py")
    require("git diff --check" in ci,
            "CI must run `git diff --check`")


# --------------------------------------------------------------------------- #
# built archives
# --------------------------------------------------------------------------- #
def test_archive_members():
    """Any archive left in dist/ must be safe to extract (no absolute paths, no
    traversal, no links) -- the same rule deploy.py enforces before upload."""
    dist = ROOT / "dist"
    if not dist.is_dir():
        return  # nothing built in this checkout (CI has no dist/)

    for archive in sorted(dist.glob("**/*.tar.gz")):
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar.getmembers():
                path = Path(member.name)
                require(not path.is_absolute(),
                        f"{archive.name}: absolute member {member.name!r}")
                require(".." not in path.parts,
                        f"{archive.name}: traversing member {member.name!r}")
                require(not (member.issym() or member.islnk()),
                        f"{archive.name}: link member {member.name!r}")

    for archive in sorted(dist.glob("**/*.zip")):
        with zipfile.ZipFile(archive) as zf:
            for name in zf.namelist():
                path = Path(name)
                require(not path.is_absolute(),
                        f"{archive.name}: absolute member {name!r}")
                require(".." not in path.parts,
                        f"{archive.name}: traversing member {name!r}")


TESTS = [
    test_packaging_script,
    test_no_committed_secrets,
    test_deploy_safety,
    test_gui_never_puts_the_key_on_the_command_line,
    test_gui_finds_the_dev_build,
    test_gui_maps_darwin_to_the_macos_bin_dir,
    test_deploy_dry_run,
    test_service_scripts,
    test_udp_buffer_ceiling_agrees,
    test_vcpkg_pins_agree,
    test_versions_agree,
    test_suffix_validation_agrees,
    test_ci_runs_this_suite_and_the_whitespace_check,
    test_archive_members,
]


def main() -> int:
    failed = []
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report every failure, not just the first
            failed.append(test.__name__)
            print(f"FAIL {test.__name__}: {exc}", file=sys.stderr)
        else:
            print(f"ok   {test.__name__}")

    total = len(TESTS)
    print()
    if failed:
        print(f"smoke tests FAILED: {len(failed)}/{total} -> {', '.join(failed)}")
        return 1
    print(f"smoke tests passed ({total}/{total})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
