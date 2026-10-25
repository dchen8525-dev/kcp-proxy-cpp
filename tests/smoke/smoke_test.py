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
import os
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]

# The key-refresh schedule. The daily key is YYYYMMDD in Beijing time (UTC+8,
# no DST), while a bare OnCalendar= is evaluated in the host's timezone, so the
# ticks are pinned to UTC: Beijing 00:00/06:00/12:00/18:00 == UTC
# 16:00/22:00/04:00/10:00. 04,10,16,22 is that set sorted.
#
# "UTC" as an OnCalendar suffix needs systemd >= 228; a full IANA name would
# need 252 and would leave the timer with no next elapse on older hosts.
BEIJING_TIMER_UTC = "*-*-* 04,10,16,22:00:00 UTC"


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


def test_server_wrappers_never_put_the_key_on_the_command_line():
    # The server is a long-lived daemon, so its command line is exposed in
    # /proc/<pid>/cmdline to every local user on Linux for the whole session.
    # The install/package wrappers must therefore derive the daily key and hand
    # it over through KCP_PROXY_KEY, never -k <key>, or they leak today's key
    # and defeat the 0600 server.env.
    install = read("scripts/deploy/install-service.sh")
    require('-k "$KEY"' not in install,
            "install-service.sh must not pass the key on the server command line")
    require('export KCP_PROXY_KEY="$KEY"' in install,
            "install-service.sh must hand the key to the server via KCP_PROXY_KEY")

    package = read("scripts/package/package.py")
    require('-k "$KEY"' not in package,
            "package.py's embedded WRAPPER_SH must not pass the key on the "
            "server command line")
    require('export KCP_PROXY_KEY="$KEY"' in package,
            "package.py's WRAPPER_SH must hand the key to the server via "
            "KCP_PROXY_KEY")

    # The two wrappers must agree on the handoff, or a stray -k reintroduces
    # the leak through whichever copy actually ships.
    require('KCP_PROXY_KEY="$KEY"' in install and 'KCP_PROXY_KEY="$KEY"' in package,
            "both server wrappers must use the same KCP_PROXY_KEY handoff")


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
# the Windows installer shows real installation details
# --------------------------------------------------------------------------- #
def test_nsis_installer_shows_details():
    """electron-builder's stock install section suppresses every status line
    with `SetDetailsPrint none`, so the Setup.exe shows a bare progress bar:
    no Extract / Output folder / Create shortcut feedback at all. The custom
    NSIS script (gui/electron/nsis/) re-enables it; guard the wiring, because
    every piece of it fails silently if dropped."""
    config = json.loads(read("gui/electron/electron-builder.win.json"))
    nsis = config.get("nsis", {})
    require(nsis.get("script") == "installer.nsi",
            'electron-builder.win.json must set nsis.script="installer.nsi"')
    # include= does double duty: its file enables ShowInstDetails AND its
    # presence is what makes electron-builder add the build resources dir to
    # the makensis include path, so installSection_details.nsh resolves.
    require(nsis.get("include") == "installer.nsh",
            'electron-builder.win.json must set nsis.include="installer.nsh"')
    require(config.get("directories", {}).get("buildResources") == "nsis",
            'buildResources must point at "nsis" (repo .gitignore ignores every '
            'build/ directory, so the NSIS scripts cannot live in build/)')
    require((ROOT / "gui" / "electron" / "nsis" / "installer.nsi").is_file(),
            "missing gui/electron/nsis/installer.nsi")

    nsi = read("gui/electron/nsis/installer.nsi")
    require('!include "installSection_details.nsh"' in nsi,
            "installer.nsi must include the patched installSection_details.nsh, "
            'not the stock "installSection.nsh"')
    require("LangString detailExtracting" in nsi,
            "installer.nsi must define the bilingual progress strings")

    section = read("gui/electron/nsis/installSection_details.nsh")
    # Match the instruction itself, not prose about it: the file documents the
    # original bug in a comment, which mentions the same words.
    require(re.search(r"^\s*SetDetailsPrint\s+none\b", section, re.MULTILINE) is None,
            "installSection_details.nsh must not re-suppress details "
            "(SetDetailsPrint none is the original bug)")
    require("SetDetailsPrint both" in section,
            "installSection_details.nsh must enable SetDetailsPrint both")
    require('DetailPrint "$(detailExtracting)"' in section,
            "installSection_details.nsh must print the extraction milestone")

    require("ShowInstDetails show" in read("gui/electron/nsis/installer.nsh"),
            "installer.nsh must show the details view by default")


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

    # The key is the Beijing date but a bare OnCalendar= is evaluated in the
    # host's timezone, so the schedule has to be pinned to UTC. A regression to
    # the host-local form ("0/6:00:00") passes every other check here -- the
    # timer still arms, it just fires up to ~14h away from the date change, so
    # clients fail DECRYPT_FAILED long after Beijing midnight. Assert the exact
    # expression in all three copies that must agree.
    #
    # Beijing 00:00/06:00/12:00/18:00 == UTC 16:00/22:00/04:00/10:00.
    for path in ("scripts/templates/kcp-proxy-server-key-refresh.timer",
                 "scripts/deploy/install-service.sh",
                 "scripts/package/package.py"):
        require(BEIJING_TIMER_UTC in read(path),
                f"{path} must schedule the key refresh at Beijing time "
                f"via the UTC expression {BEIJING_TIMER_UTC!r}")
    require(BEIJING_TIMER_UTC not in read("scripts/deploy/install-service.sh")
            or "systemd-analyze calendar" in install,
            "the UTC schedule needs a systemd-analyze probe, or systemd < 228 "
            "silently leaves the timer unarmed")

    require(BEIJING_TIMER_UTC not in read("scripts/deploy/install-service.sh")
            or "systemd-analyze calendar" in install,
            "the UTC schedule needs a systemd-analyze probe, or systemd < 228 "
            "silently leaves the timer unarmed")

    # ... and the probe must be able to fall back, or the UTC expression is a
    # hard dependency on systemd >= 228 rather than a preference.
    for path in ("scripts/deploy/install-service.sh", "scripts/package/package.py"):
        text = read(path)
        require("systemd-analyze calendar" in text,
                f"{path} must probe whether the UTC OnCalendar suffix parses")
        require("date +%z" in text,
                f"{path} must derive the local fallback from the host's UTC offset")

    # Both fallback copies run under POSIX sh in the deb postinst, where bashisms
    # abort the whole install: $((10#...)) and ${var:off:len} are both bash-only.
    # Whole-line comments are skipped -- they legitimately name the bashisms --
    # but code lines must be scanned whole: stripping a trailing "# comment"
    # would cut "$(( 10#oh ..." down to "$(( 10" and hide the very syntax the
    # check exists to catch.
    for path in ("scripts/deploy/install-service.sh", "scripts/package/package.py"):
        code = "\n".join(
            line for line in read(path).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        require("10#" not in code,
                f"{path} must not use the bash-only $((10#..)) base prefix in "
                f"the timer fallback (the deb postinst runs under dash)")
        require("${_first:" not in code and "${first:" not in code,
                f"{path} must not use bash substring expansion in the timer "
                f"fallback (the deb postinst runs under dash)")

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


# --------------------------------------------------------------------------- #
# GUI icon assets (taskbar / tray)
# --------------------------------------------------------------------------- #
def test_gui_icon_assets_are_valid():
    """The 2026-10-17 incident: the shipped 米纸白 tile read as a white square
    at taskbar size and the tray never showed the app icon. These checks pin
    the shape of the assets so a regeneration cannot silently ship a broken,
    truncated or low-contrast icon again."""
    assets = ROOT / "gui" / "electron" / "assets"

    png = (assets / "icon.png").read_bytes()
    require(png[:8] == b"\x89PNG\r\n\x1a\n", "icon.png is not a PNG file")
    require(len(png) >= 24, "icon.png is truncated")
    width, height = struct.unpack(">II", png[16:24])
    require((width, height) == (512, 512),
            f"icon.png must be a 512x512 master, got {width}x{height}")
    require(png[25] == 6,
            f"icon.png must be 8-bit RGBA (color type 6), got {png[25]}")

    ico = (assets / "icon.ico").read_bytes()
    require(ico[:4] == b"\x00\x00\x01\x00",
            "icon.ico must start with the ICO magic (reserved=0, type=1)")
    count = struct.unpack("<H", ico[4:6])[0]
    require(count >= 4, f"icon.ico must carry at least 4 sizes, got {count}")
    sizes = []
    for i in range(count):
        off = 6 + i * 16
        w, _h, _ncol, _res, _planes, bpp, size, offset = struct.unpack(
            "<BBBBHHII", ico[off:off + 16])
        entry = ico[offset:offset + size]
        is_png = entry[:8] == b"\x89PNG\r\n\x1a\n"
        is_bmp = len(entry) >= 4 and struct.unpack("<I", entry[:4])[0] == 40
        require(is_png or is_bmp,
                f"icon.ico entry {i} is neither a PNG nor a BMP payload")
        require(bpp == 32, f"icon.ico entry {i} must be 32bpp, got {bpp}")
        sizes.append(w or 256)
    require(256 in sizes,
            "icon.ico must contain a 256x256 entry (Windows shell requirement)")
    require(16 in sizes,
            "icon.ico must contain a 16x16 entry (tray / small taskbar)")

    svg = (assets / "icon.svg").read_text(encoding="utf-8")
    for color in ("#26221a", "#b5432f"):
        require(color in svg,
                f"icon.svg must keep the styles.css palette color {color}")


def test_gui_builder_and_tray_icons_wired():
    """The runtime window/tray icon comes from assets/icon.png, and the EXE /
    shortcut icon is embedded by electron-builder. A wrong path or format here
    silently falls back to the default Electron icon -- a white square in the
    taskbar, exactly the reported symptom."""
    base = json.loads(read("gui/electron/electron-builder.base.json"))
    for pattern in ("assets/*.png", "assets/*.ico"):
        require(pattern in base["files"],
                f"electron-builder.base.json must package {pattern}")

    win = json.loads(read("gui/electron/electron-builder.win.json"))
    portable = json.loads(read("gui/electron/electron-builder.portable.json"))
    linux = json.loads(read("gui/electron/electron-builder.linux.json"))

    # rcedit embeds the Windows EXE icon and wants a classic multi-size .ico;
    # the ICO is also the documented format and skips the icons-CLI conversion.
    require(win["win"]["icon"] == "assets/icon.ico",
            "electron-builder.win.json win.icon must be assets/icon.ico")
    require(portable["win"]["icon"] == "assets/icon.ico",
            "electron-builder.portable.json win.icon must be assets/icon.ico")
    require(linux["linux"]["icon"] == "assets/icon.png",
            "electron-builder.linux.json linux.icon must be assets/icon.png")

    for config, key in ((win, "win"), (portable, "win"), (linux, "linux")):
        rel = config[key]["icon"]
        require((ROOT / "gui" / "electron" / rel).is_file(),
                f"{rel} referenced by the {key} builder config does not exist")

    # The tray regression itself, frozen as a contract: the tray image is the
    # app icon resolved from the packaged assets, and nothing may override it
    # with a programmatic substitute (that is how the icon disappeared).
    main_js = read("gui/electron/main.js")
    require("resolveAppIconPath" in main_js,
            "main.js must resolve the tray icon through resolveAppIconPath")
    require("setImage" not in main_js,
            "main.js must not override the tray image (status lives in the tooltip)")
    require("createStatusIcon" not in main_js,
            "main.js must not carry the retired programmatic status-icon code")


# --------------------------------------------------------------------------- #
# uninstaller (the 2026-10-17 "reported success, deleted nothing" incident)
# --------------------------------------------------------------------------- #
def _client_executable_name() -> str:
    """The installed file name of the proxy client, straight from the builder
    config -- so renaming the binary fails this suite instead of silently
    un-protecting it."""
    win = json.loads(read("gui/electron/electron-builder.win.json"))
    names = {Path(entry["to"]).name
             for entry in win.get("extraResources", [])}
    require("kcp-proxy-client.exe" in names,
            f"the proxy client must ship via win extraResources, got {names}")
    return "kcp-proxy-client.exe"


def test_uninstaller_kills_the_client_process():
    """The GUI spawns kcp-proxy-client.exe as a child (image at
    $INSTDIR\\resources). Force-killing the GUI (taskkill /F) bypasses the
    app's own before-quit reaper, and a crashed GUI leaves the client orphaned
    the same way -- either path keeps $INSTDIR\\resources locked and RMDir /r
    then silently skips those files: "uninstall succeeded" with the whole
    directory left behind. The stock check only knew ${APP_EXECUTABLE_FILENAME}."""
    nsh = read("gui/electron/nsis/uninstaller_details.nsh")
    client = _client_executable_name()
    for macro in ("FIND_PROCESS", "KILL_PROCESS"):
        require(f'!insertmacro {macro} "{client}"' in nsh,
                f"uninstaller_details.nsh must {macro.replace('_', ' ')} "
                f"the client process, not only the GUI exe")


def test_uninstaller_kills_gui_before_client():
    """Order matters: the GUI respawns the client the moment it dies
    (auto-reconnect), so the client may only be terminated once the GUI is
    gone."""
    nsh = read("gui/electron/nsis/uninstaller_details.nsh")
    gui = nsh.find('!insertmacro KILL_PROCESS "${APP_EXECUTABLE_FILENAME}"')
    client = nsh.find(f'!insertmacro KILL_PROCESS '
                      f'"{_client_executable_name()}"')
    require(gui != -1, "GUI kill missing from uninstaller_details.nsh")
    require(client != -1, "client kill missing from uninstaller_details.nsh")
    require(gui < client,
            "the client must be killed only after the GUI (the GUI's "
            "reconnect logic respawns it)")


def test_uninstaller_verifies_removal():
    """RMDir /r silently skips files that are still locked, so the section
    must check afterwards, retry the kill once, and surface leftovers instead
    of claiming success."""
    nsh = read("gui/electron/nsis/uninstaller_details.nsh")
    require(nsh.count("Call un.killAppProcesses") >= 2,
            "the uninstall section must retry the kill after a failed RMDir")
    require('IfFileExists "$INSTDIR\\*.*"' in nsh,
            "the uninstall section must verify $INSTDIR is really gone")
    require("RMDir /r $INSTDIR" in nsh,
            "the uninstall section must still remove the install directory")

    nsi = read("gui/electron/nsis/installer.nsi")
    for name in ("uninstallIncomplete", "uninstallNoDir"):
        require(f"LangString {name}" in nsi,
                f"installer.nsi must define the bilingual {name} warning")
    require("$(uninstallIncomplete)" in nsh,
            "uninstaller_details.nsh must surface the leftover warning")


def test_uninstaller_refuses_empty_installdir():
    """An empty $INSTDIR turns RMDir /r into a silent no-op while the rest of
    the section (registry, shortcuts) still runs -- "success" with everything
    left behind. Refuse loudly instead."""
    nsh = read("gui/electron/nsis/uninstaller_details.nsh")
    require('${if} $INSTDIR == ""' in nsh,
            "the uninstall section must detect an unresolvable $INSTDIR")
    require("$(uninstallNoDir)" in nsh,
            "the empty-$INSTDIR branch must report the bilingual error")
    # The refusal must abort the section, not fall through to a silent success.
    idx = nsh.find('${if} $INSTDIR == ""')
    require("Abort" in nsh[idx:idx + 500],
            "the empty-$INSTDIR branch must Abort the section")


def _strip_nsis_comment(line: str) -> str:
    """Drop a trailing NSIS line comment (# or ;) from one line, honouring
    double quotes so tokens inside strings ("gui not running; checking...")
    survive. Without this, a comment merely MENTIONING `!ifdef` desynchronises
    the conditional pairing counts below (a false positive that blocks CI)."""
    out = []
    in_str = False
    for ch in line:
        if ch == '"':
            in_str = not in_str
        if not in_str and ch in "#;":
            break
        out.append(ch)
    return "".join(out)


def test_uninstaller_file_removal_is_reachable():
    """Root cause of the 2026-10-17 incident: the patched uninstaller carried
    `${else}` where the stock template has `!else`. The NSIS preprocessor does
    not know `${else}` (a runtime LogicLib token), so `!ifmacrodef
    customRemoveFiles` -- and customRemoveFiles is never defined -- jumped
    straight to `!endif`, making the whole else-branch dead code. RMDir /r
    $INSTDIR never ran, yet the section continued to the registry and
    shortcut cleanup: "卸载成功" with every file still on disk. Pin the
    preprocessor pairing so the removal block can never go dead again."""
    for name in ("uninstaller_details.nsh", "installSection_details.nsh",
                 "installer.nsh", "installer.nsi"):
        text = read(f"gui/electron/nsis/{name}")
        pp_depth = 0   # preprocessor !if...def / !endif nesting
        rt_depth = 0   # runtime ${If}...${EndIf} nesting
        for lineno, line in enumerate(text.split("\n"), 1):
            code = _strip_nsis_comment(line)
            stripped = code.strip()
            pp_depth += len(re.findall(r"!if(macro)?(n)?def\b", code))
            pp_depth -= len(re.findall(r"!endif\b", code))
            # A runtime ${else} is only legal while a runtime ${If...} is
            # open. With no runtime if open it can only be a mistyped
            # preprocessor else -- the incident pattern.
            if stripped == "${else}":
                require(rt_depth > 0,
                        f"{name}:{lineno}: ${{else}} with no open runtime "
                        "${{If}} -- this is the incident typo: inside a "
                        "!if...def block it makes the else-branch dead code")
            rt_depth += len(re.findall(
                r"\$\{[iI]f(?:[nN]ot)?\b", code))
            rt_depth -= len(re.findall(r"\$\{[eE]nd[iI]f\b", code))
        require(pp_depth == 0,
                f"{name} has unbalanced preprocessor conditionals "
                f"(depth {pp_depth})")

    nsh = read("gui/electron/nsis/uninstaller_details.nsh")
    require("!ifmacrodef customRemoveFiles" in nsh,
            "the stock customRemoveFiles hook must stay wired")
    require("RMDir /r $INSTDIR" in nsh,
            "the install directory removal must stay in the script")


def test_uninstaller_pid_fetch_cannot_clobber_installdir():
    """2026-10-17 second incident: `System::Call
    'Kernel32::GetProcessId(i R0) i.pid'` used a bare NAME as the output
    destination. That is not a variable reference: empirically (makensis
    micro-probe, verified against the field trace log) the System plugin
    writes the return value into $INSTDIR and leaves $pid empty -- so the
    uninstaller ran `RMDir /r 8652` (its own pid) and the removal check
    passed trivially while the real directory stayed on disk. Pin the safe
    forms: the pid must be fetched into a plain register and copied."""
    nsh = read("gui/electron/nsis/uninstaller_details.nsh")
    require("StrCpy $pid $R" in nsh,
            "the current pid must be copied from a register into $pid")
    # The dotted output form (.R0) is equally broken: it silently writes
    # nothing, so a refactor to it would leave $pid empty and taskkill's
    # "PID ne " filter malformed.
    require(re.search(r"System::Call '[^']*\)\s*\.\w", nsh) is None,
            "System::Call must not use the dotted output form (writes "
            "nothing); use a plain register (i.R2) or the stack (i.s)")
    require("i.pid" not in nsh,
            "the bare-name output destination i.pid must never come back "
            "(it clobbers $INSTDIR with the pid)")


def test_uninstaller_orphan_client_kill_is_unconditional():
    """The GUI-not-running branch is taken exactly when $R0 != 0, so guarding
    the orphaned-client kill with `${if} $R0 == 0` makes it dead code -- an
    orphaned client then survives every uninstall with the GUI already gone,
    which is the one scenario the check exists for."""
    nsh = read("gui/electron/nsis/uninstaller_details.nsh")
    branch = nsh.find("gui not running; checking for an orphaned client")
    require(branch != -1, "the orphan-client trace marker must stay")
    tail = nsh[branch:nsh.find("${endIf}", branch)]
    require("Call un.killAppProcesses" in tail,
            "the orphaned client must be killed in the GUI-not-running branch")
    require("${if} $R0 == 0" not in tail,
            "the orphaned-client kill must NOT be guarded by ${if} $R0 == 0 "
            "-- inside the ${else} branch that condition is always false "
            "(dead code)")


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


def test_deb_postinst_generates_suffix_and_resets_failed():
    """First-install deb experience: the shipped server.env carries an empty
    SUFFIX (the package is public -- embedding one would leak key material)
    and the wrapper refuses to start without it. The postinst must therefore
    (a) generate a random suffix before restarting, or every fresh
    `apt install` fails five times into a start-limit latch, and (b) reset
    the failed-unit state before restarting, or an earlier crash loop
    refuses the very restart that was supposed to fix the configuration.
    Field incident 2026-10-17: the user's manual restart hit start-limit-hit
    and looked like 'the deb is broken' while the service was actually fine.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "package"))
    import package  # noqa: E402

    postinst = package.DEB_POSTINST

    # Static ordering: generate suffix -> reset-failed -> restart. Any restart
    # that can run before the suffix exists re-creates the 0.0.19 incident.
    gen_at = postinst.find("/dev/urandom")
    reset_at = postinst.find("systemctl reset-failed")
    restart_at = postinst.rfind('systemctl restart "$SERVICE_NAME"')
    require(gen_at != -1,
            "postinst must generate a random suffix via /dev/urandom when "
            "the shipped server.env has an empty SUFFIX")
    require(reset_at != -1,
            "postinst must systemctl reset-failed before restarting, or a "
            "start-limit latch from earlier failures refuses the restart")
    require(gen_at < reset_at < restart_at,
            "postinst ordering must be: generate suffix -> reset-failed -> "
            "restart (restart_at is the LAST restart; an earlier one is fatal)")

    # The generated suffix must actually land in server.env, and the file must
    # stay 0600 -- it holds the long-lived half of the daily key.
    require('sed "s|^SUFFIX=.*|SUFFIX=$gen_suffix|"' in postinst,
            "postinst must write the generated suffix into the existing "
            "server.env via sed (a full-file rewrite would clobber PORT/HOST)")
    require("chmod 600" in postinst,
            "postinst must keep server.env at 0600 after writing the suffix")

    # Runtime: execute the rendered generation block under a real POSIX shell.
    # Static reading is exactly how the i.pid trap survived review.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import beijing_timer_schedule_check as bj

    i = postinst.index('        env_file="/etc/kcp-proxy/server.env"')
    j = postinst.index("systemctl reset-failed", i)
    block = postinst[i:j]
    require("sed -i" not in block,
            "the suffix block must not use sed -i: BSD sed takes the next "
            "argument as the backup suffix and silently modifies nothing "
            "(the first 0.0.20 CI run failed on macos for exactly this)")

    # A single pipeline pass has been observed to return a SHORT suffix on a
    # loaded runner (CI 2026-10-21 macos dash got '4'); a short suffix would
    # mint a silently-wrong daily key. Pin the retry-until-24 loop.
    require('while [ "${#gen_suffix}" -lt 24 ]' in postinst,
            "suffix generation must retry until 24 chars before writing")

    shell = bj.resolve_shell("bash")
    if shell:
        tmp = Path(tempfile.mkdtemp())
        env_file = tmp / "server.env"
        # Render: the f-string already substituted the real /etc paths; point
        # them at the sandbox. Longer path first or the dir rewrite would
        # corrupt the file path.
        block = block.replace("/etc/kcp-proxy/server.env", str(env_file).replace("\\", "/"))
        block = block.replace("/etc/kcp-proxy", str(tmp).replace("\\", "/"))

        def run(block_text, sh=shell):
            script = tmp / "probe.sh"
            script.write_bytes(block_text.encode("utf-8"))
            return subprocess.run([sh, bj.to_posix(script)],
                                  capture_output=True, text=True,
                                  encoding="utf-8", errors="replace")

        # Shared diagnostic probe (CI 2026-10-21 macos: the dash case once
        # produced a 1-char suffix; without this probe such a failure names
        # no tool). Created up front so BOTH case A and the dash case can
        # attach its output to their failure messages.
        diag = tmp / "diag.sh"
        diag.write_bytes((
            'for t in head tr od sed mv grep cut; do command -v "$t" >/dev/null '
            '&& echo "tool $t: ok" || echo "tool $t: MISSING"; done\n'
            'g1=$(head -c 2048 /dev/urandom | tr -dc "a-f0-9" | head -c 24)\n'
            'echo "tr_pipeline_len=${#g1}"\n'
            'g2=$(od -An -N 32 -t x1 /dev/urandom 2>/dev/null | tr -d " \\n" | cut -c1-24)\n'
            'echo "od_pipeline_len=${#g2}"\n'
            'sed "s|^SUFFIX=.*|SUFFIX=DEADBEEF|" "$1" > "$1.diag" && '
            'mv -f "$1.diag" "$1" && echo "sed_mv: ok" || echo "sed_mv: FAILED rc=$?"\n'
        ).encode("utf-8"))

        # Case A: shipped conffile with empty SUFFIX -> gets a 24-char suffix,
        # other lines preserved.
        env_file.write_bytes(
            b"SUFFIX=\nPORT=8388\nHOST=0.0.0.0\nLOG_FILE=/var/log/kcp-proxy/server.log\n")
        proc = run(block)
        require(proc.returncode == 0,
                f"suffix generation must succeed, got exit {proc.returncode}: "
                f"{proc.stderr.strip()[:200]}")
        got = dict(
            line.split("=", 1) for line in
            env_file.read_text(encoding="utf-8").strip().splitlines()
            if "=" in line and not line.startswith("#"))
        if re.fullmatch(r"[0-9a-f]{24}", got.get("SUFFIX", "")) is None:
            # Evidence first: run each pipeline stage in isolation so the
            # failure message names the broken tool instead of just the
            # symptom (the macos runner needed two rounds of this).
            d = subprocess.run([shell, bj.to_posix(diag), str(env_file).replace("\\", "/")],
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
            require(False,
                    f"generated suffix must be 24 hex chars, got "
                    f"{got.get('SUFFIX')!r}; file={env_file.read_text(encoding='utf-8')!r}; "
                    f"block stdout={proc.stdout!r} stderr={proc.stderr!r}; "
                    f"diag:\n{d.stdout}{d.stderr}")
        require(got.get("PORT") == "8388" and got.get("HOST") == "0.0.0.0",
                "suffix generation must not clobber the other env lines")
        require(got["SUFFIX"] != "0" * 24, "generated suffix must not be trivial")

        # Case B: an already-configured suffix is never overwritten.
        env_file.write_bytes(b"SUFFIX=mysecret123\nPORT=9000\n")
        run(block)
        content = env_file.read_text(encoding="utf-8")
        require("SUFFIX=mysecret123" in content and "PORT=9000" in content,
                "postinst must leave a configured SUFFIX untouched")

        # Case C: missing conffile (dpkg conffile prompt declined, etc.) ->
        # the file is created, not a silent no-op. The FEC-ensure block also
        # lands here, so the created file is SUFFIX plus the (empty) FEC line
        # the wrapper's auto-adapt default reads.
        env_file.unlink()
        run(block)
        require(env_file.exists()
                and re.fullmatch(r"SUFFIX=[0-9a-f]{24}\n(FEC=\n)?",
                                 env_file.read_text(encoding="utf-8")) is not None,
                "postinst must create server.env when it is missing")

        # The real postinst runs under dash on Debian (bashisms already bit
        # this repo once), so case A must also pass there when dash exists.
        dash = bj.resolve_shell("dash")
        if dash and dash != shell:
            env_file.write_bytes(b"SUFFIX=\nPORT=8388\n")
            proc_dash = run(block, sh=dash)
            require(proc_dash.returncode == 0,
                    f"suffix generation must succeed under dash, got exit "
                    f"{proc_dash.returncode}: {proc_dash.stderr.strip()[:200]}")
            got_dash = dict(
                line.split("=", 1) for line in
                env_file.read_text(encoding="utf-8").strip().splitlines()
                if "=" in line and not line.startswith("#"))
            if re.fullmatch(r"[0-9a-f]{24}", got_dash.get("SUFFIX", "")) is None:
                # Same evidence-first rule as case A: name the broken tool,
                # under the SAME shell that failed (CI 2026-10-21 macos).
                d = subprocess.run([dash, bj.to_posix(diag), str(env_file).replace("\\", "/")],
                                   capture_output=True, text=True,
                                   encoding="utf-8", errors="replace")
                require(False,
                        f"dash run must produce a 24-hex suffix, got "
                        f"{got_dash.get('SUFFIX')!r}; file={env_file.read_text(encoding='utf-8')!r}; "
                        f"block stdout={proc_dash.stdout!r} stderr={proc_dash.stderr!r}; "
                        f"diag:\n{d.stdout}{d.stderr}")

        # Case D: mode must be 0600 after generation (key material lives here).
        if os.name == "nt":
            # MSYS maps the POSIX bits onto Windows ACLs; stat() mode here is
            # not evidence of anything. The chmod 600 static check above and
            # the ubuntu CI run carry this contract.
            pass
        else:
            mode = os.stat(env_file).st_mode & 0o777
            require(mode == 0o600,
                    f"server.env must be 0600 after generation, got {oct(mode)}")
    else:
        # No POSIX shell at all: the static ordering checks above still ran,
        # and the runtime half is covered on the ubuntu smoke job.
        print("SKIP runtime part: no POSIX shell found")


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


def test_beijing_timer_schedule_converts_at_runtime():
    """Execute the UTC-offset fallback in both copies and check the arithmetic.

    The static checks above prove the schedule is written in UTC; this one
    proves the fallback actually lands on Beijing 00/06/12/18 from an arbitrary
    host offset, under both bash and dash. A conversion bug would otherwise only
    surface as "clients fail DECRYPT_FAILED for hours" on a non-Beijing host.
    """
    check = ROOT / "tests" / "smoke" / "beijing_timer_schedule_check.py"
    require(check.is_file(), "missing tests/smoke/beijing_timer_schedule_check.py")
    proc = subprocess.run(
        [sys.executable, str(check)], capture_output=True, text=True, cwd=str(ROOT)
    )
    require(
        proc.returncode == 0,
        "the Beijing-time schedule conversion failed at runtime:\n"
        + proc.stdout
        + proc.stderr,
    )


TESTS = [
    test_packaging_script,
    test_no_committed_secrets,
    test_deploy_safety,
    test_gui_never_puts_the_key_on_the_command_line,
    test_server_wrappers_never_put_the_key_on_the_command_line,
    test_gui_finds_the_dev_build,
    test_gui_maps_darwin_to_the_macos_bin_dir,
    test_nsis_installer_shows_details,
    test_deploy_dry_run,
    test_service_scripts,
    test_beijing_timer_schedule_converts_at_runtime,
    test_udp_buffer_ceiling_agrees,
    test_vcpkg_pins_agree,
    test_versions_agree,
    test_gui_icon_assets_are_valid,
    test_gui_builder_and_tray_icons_wired,
    test_uninstaller_kills_the_client_process,
    test_uninstaller_kills_gui_before_client,
    test_uninstaller_verifies_removal,
    test_uninstaller_refuses_empty_installdir,
    test_uninstaller_file_removal_is_reachable,
    test_suffix_validation_agrees,
    test_deb_postinst_generates_suffix_and_resets_failed,
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
