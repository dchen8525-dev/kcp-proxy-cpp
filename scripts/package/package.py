#!/usr/bin/env python3
"""Unified packaging for kcp-proxy.

Replaces the former `package.sh` / `package-standalone.sh` / `package-deb.sh`.

Pure standard library (no bash, tar, zip/7z, sha256sum, install, mktemp), so it
runs unchanged on Linux, macOS and Windows. Written against Python 3.12 but
deliberately kept compatible with Python 3.9+ for CI runners.

File permissions inside every archive come from an explicit table, never from
`stat()`: Windows has no Unix mode bits, and reading them there would silently
ship non-executable binaries.

Usage:
    python3 scripts/package/package.py standalone [--os OS] [--arch ARCH]
    python3 scripts/package/package.py deb [--arch ARCH]
    python3 scripts/package/package.py            # alias for `standalone`

Environment overrides (kept from the shell version):
    KCP_PACKAGE_OS     force the target OS   (linux | macos | windows)
    KCP_PACKAGE_ARCH   force the target arch (x64 | arm64 | amd64 | ...)

Outputs (unchanged layout):
    dist/releases/<version>/kcp-proxy-<version>-<os>-<arch>.tar.gz   (linux/macos)
    dist/releases/<version>/kcp-proxy-<version>-<os>-<arch>.zip      (windows)
    dist/releases/<version>/kcp-proxy-server_<version>_<arch>.deb    (deb)
    dist/releases/<version>/SHA256SUMS
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import lzma
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
DIST_DIR = ROOT_DIR / "dist"
STAGING_DIR = DIST_DIR / "staging"
CMAKE_VERSION_RE = re.compile(r"VERSION\s+(\d+\.\d+\.\d+)")

# Shared server-side defaults. Keep in sync with scripts/runtime/common.sh.
SERVER_PORT = 8388
SERVER_HOST = "0.0.0.0"
LOG_LEVEL = "INFO"
INSTALL_DIR = "/usr/local/bin/kcp-proxy"
ENV_DIR = "/etc/kcp-proxy"
ENV_FILE = f"{ENV_DIR}/server.env"
SERVICE_NAME = "kcp-proxy-server.service"
SERVICE_USER = "kcpproxy"
PKG_NAME = "kcp-proxy-server"

MODE_EXEC = 0o755
MODE_FILE = 0o644
MODE_SECRET = 0o600

# Explicit permissions for the .deb payload. Never derived from the build host.
DEB_MODES = {
    "./usr/local/bin/kcp-proxy/kcp-proxy-server": MODE_EXEC,
    "./usr/local/bin/kcp-proxy/kcp-proxy-server-wrapper.sh": MODE_EXEC,
    "./etc/kcp-proxy/server.env": MODE_SECRET,
    "./etc/systemd/system/kcp-proxy-server.service": MODE_FILE,
    "./etc/systemd/system/kcp-proxy-server-key-refresh.service": MODE_FILE,
    "./etc/systemd/system/kcp-proxy-server-key-refresh.timer": MODE_FILE,
}
DEB_CONTROL_MODES = {
    "./postinst": MODE_EXEC,
    "./prerm": MODE_EXEC,
    "./postrm": MODE_EXEC,
    "./control": MODE_FILE,
    "./conffiles": MODE_FILE,
    "./md5sums": MODE_FILE,
}


class PackageError(Exception):
    """Fatal, user-facing packaging error."""


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def project_version() -> str:
    """Read the version from CMakeLists.txt (same rule the shell scripts used)."""
    cmake = ROOT_DIR / "CMakeLists.txt"
    if not cmake.is_file():
        raise PackageError(f"CMakeLists.txt not found at {cmake}")
    for line in cmake.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = CMAKE_VERSION_RE.search(line)
        if match:
            return match.group(1)
    raise PackageError("cannot determine project version from CMakeLists.txt")


def detect_os() -> str:
    system = platform.system()
    if system == "Linux":
        return "linux"
    if system == "Darwin":
        return "macos"
    if system == "Windows":
        return "windows"
    # Git Bash / MSYS2 / Cygwin report MINGW64_NT-... or CYGWIN_NT-...
    if system.startswith(("MINGW", "MSYS", "CYGWIN")):
        return "windows"
    raise PackageError(f"unsupported host platform: {system}")


def detect_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "arm64"
    return "x64"


def normalize_deb_arch(value):
    """Debian architecture: query dpkg when possible, else fall back to amd64."""
    if value:
        lowered = value.lower()
        if lowered in ("x64", "amd64", "x86_64"):
            return "amd64"
        if lowered in ("arm64", "aarch64"):
            return "arm64"
        return lowered
    if shutil.which("dpkg"):
        try:
            out = subprocess.run(
                ["dpkg", "--print-architecture"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            if out:
                return out
        except (subprocess.SubprocessError, OSError):
            pass
    return "amd64"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def update_sha256_sums(release_dir: Path, archive: Path) -> Path:
    """Record the archive checksum, replacing any previous entry for that file."""
    release_dir.mkdir(parents=True, exist_ok=True)
    sums = release_dir / "SHA256SUMS"
    kept = []
    if sums.exists():
        for line in sums.read_text(encoding="utf-8").splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[1].strip() != archive.name:
                kept.append(line)
    kept.append(f"{sha256_of(archive)}  {archive.name}")
    sums.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return sums


def write_text(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, mode)


def copy_file(src: Path, dst: Path, mode: int) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    os.chmod(dst, mode)


def new_stage_dir(prefix: str) -> Path:
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(STAGING_DIR)))


# --------------------------------------------------------------------------- #
# embedded server-side payloads (executed on the target host, stay POSIX sh)
# --------------------------------------------------------------------------- #
WRAPPER_SH = """\
#!/bin/sh
# Wrapper: derives daily key = YYYYMMDD (Beijing time) + SUFFIX.
# SUFFIX/PORT/HOST/LOG_LEVEL come from EnvironmentFile=/etc/kcp-proxy/server.env
set -eu

SUFFIX="${SUFFIX:?SUFFIX not set - check /etc/kcp-proxy/server.env}"
PORT="${PORT:-8388}"
HOST="${HOST:-0.0.0.0}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

DATE_BEIJING=$(TZ=Asia/Shanghai date +%Y%m%d)
KEY="${DATE_BEIJING}${SUFFIX}"

# Never log the full key - only the date portion and suffix length.
echo "Starting kcp-proxy-server  key_date=${DATE_BEIJING}  suffix_len=${#SUFFIX}  port=${PORT}"
exec /usr/local/bin/kcp-proxy/kcp-proxy-server -k "$KEY" -p "$PORT" -H "$HOST" -L "$LOG_LEVEL"
"""

SERVER_ENV = f"""\
# kcp-proxy-server configuration
# Daily key = YYYYMMDD (Beijing time) + SUFFIX. Changes take effect on restart.
SUFFIX=
PORT={SERVER_PORT}
HOST={SERVER_HOST}
LOG_LEVEL={LOG_LEVEL}
"""

SYSTEMD_UNIT = f"""\
[Unit]
Description=KCP Proxy Server
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/dchen8525-dev/kcp-proxy-cpp
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User={SERVICE_USER}
EnvironmentFile=-{ENV_FILE}
ExecStart={INSTALL_DIR}/kcp-proxy-server-wrapper.sh
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535
UMask=0077
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
"""

DEB_POSTINST = f"""\
#!/bin/sh
set -e
case "$1" in
    configure)
        SERVICE_USER={SERVICE_USER}
        SERVICE_NAME={SERVICE_NAME}

        # service user (harmless if already present)
        if ! id "$SERVICE_USER" >/dev/null 2>&1; then
            useradd --system --no-create-home --shell /sbin/nologin "$SERVICE_USER"
        fi

        # defensively migrate from a legacy @template unit
        if [ -f /etc/systemd/system/kcp-proxy-server@.service ]; then
            rm -f /etc/systemd/system/kcp-proxy-server@.service
            systemctl daemon-reload || true
        fi

        systemctl daemon-reload
        systemctl enable "$SERVICE_NAME" >/dev/null
        systemctl restart "$SERVICE_NAME"

        systemctl enable --now kcp-proxy-server-key-refresh.timer
        ;;
esac
exit 0
"""

DEB_PRERM = f"""\
#!/bin/sh
set -e
SERVICE_NAME={SERVICE_NAME}
case "$1" in
    remove|upgrade|deconfigure)
        systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
        systemctl disable --now kcp-proxy-server-key-refresh.timer >/dev/null 2>&1 || true
        # Configuration is preserved by dpkg as a conffile on remove.
        ;;
esac
exit 0
"""

DEB_POSTRM = f"""\
#!/bin/sh
set -e
SERVICE_NAME={SERVICE_NAME}
SERVICE_USER={SERVICE_USER}
case "$1" in
    remove)
        # remove the only kept-back unit file; dpkg removes the rest
        rm -f "/etc/systemd/system/$SERVICE_NAME"
        rm -f /etc/systemd/system/kcp-proxy-server-key-refresh.service /etc/systemd/system/kcp-proxy-server-key-refresh.timer
        systemctl daemon-reload >/dev/null 2>&1 || true
        if id "$SERVICE_USER" >/dev/null 2>&1; then
            userdel "$SERVICE_USER" 2>/dev/null || true
        fi
        ;;
    purge)
        rm -rf {ENV_DIR}
        ;;
esac
exit 0
"""


# --------------------------------------------------------------------------- #
# standalone CLI package (tar.gz for linux/macos, zip for windows)
# --------------------------------------------------------------------------- #
def build_standalone(os_name: str, arch: str) -> Path:
    """Bundle server/client/README into dist/releases/<version>."""
    version = project_version()
    if os_name == "windows":
        bin_dir = ROOT_DIR / "bin" / "windows"
        ext = ".exe"
        archive_ext = "zip"
    else:
        bin_dir = ROOT_DIR / "bin" / os_name
        ext = ""
        archive_ext = "tar.gz"

    name = f"kcp-proxy-{version}-{os_name}-{arch}"
    release_dir = DIST_DIR / "releases" / version
    release_dir.mkdir(parents=True, exist_ok=True)

    server_bin = bin_dir / f"kcp-proxy-server{ext}"
    client_bin = bin_dir / f"kcp-proxy-client{ext}"
    readme = ROOT_DIR / "README.md"
    for required in (server_bin, client_bin, readme):
        if not required.is_file():
            raise PackageError(f"required file not found: {required}")

    dlls = []
    if os_name == "windows":
        dlls = sorted(bin_dir.glob("*.dll"))
        if not dlls:
            raise PackageError(f"Windows runtime DLLs not found in {bin_dir}")

    # (archive path, source, mode) - permissions are declared, never sniffed.
    entries = [
        (f"{name}/kcp-proxy-server{ext}", server_bin, MODE_EXEC),
        (f"{name}/kcp-proxy-client{ext}", client_bin, MODE_EXEC),
        (f"{name}/README.md", readme, MODE_FILE),
    ]
    entries += [(f"{name}/{dll.name}", dll, MODE_EXEC) for dll in dlls]

    stage_root = new_stage_dir(prefix=f"pkg-{version}-")
    stage = stage_root / name
    try:
        stage.mkdir(parents=True, exist_ok=True)
        for arcname, source, mode in entries:
            copy_file(source, stage_root / arcname, mode)
        write_text(stage / "VERSION", f"{version}\n", MODE_FILE)
        write_text(
            stage / "manifest.json",
            "{\n"
            f'  "version": "{version}",\n'
            f'  "os": "{os_name}",\n'
            f'  "arch": "{arch}",\n'
            '  "component": "cli"\n'
            "}\n",
            MODE_FILE,
        )
        extra = [
            (f"{name}/VERSION", stage / "VERSION", MODE_FILE),
            (f"{name}/manifest.json", stage / "manifest.json", MODE_FILE),
        ]

        archive = release_dir / f"{name}.{archive_ext}"
        if archive_ext == "tar.gz":
            _make_tar_gz(archive, name, entries + extra)
        else:
            _make_zip(archive, entries + extra)
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)

    sums = update_sha256_sums(release_dir, archive)
    print(f"Package: {archive}")
    print(f"SHA256SUMS: {sums}")
    return archive


def _tar_dir_info(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = MODE_EXEC
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    return info


def _make_tar_gz(archive: Path, root_name: str, entries) -> None:
    with tarfile.open(archive, "w:gz", format=tarfile.GNU_FORMAT) as tar:
        tar.addfile(_tar_dir_info(root_name))
        for arcname, source, mode in entries:
            data = source.read_bytes()
            info = tarfile.TarInfo(arcname)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            info.type = tarfile.REGTYPE
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            tar.addfile(info, io.BytesIO(data))


def _make_zip(archive: Path, entries) -> None:
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, source, mode in entries:
            stamp = time.localtime(source.stat().st_mtime)[:6]
            info = zipfile.ZipInfo(arcname, date_time=stamp)
            info.external_attr = (mode & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, source.read_bytes())


# --------------------------------------------------------------------------- #
# .deb package
# --------------------------------------------------------------------------- #
def build_deb(arch) -> Path:
    """Build the systemd-service Debian package for the server component."""
    version = project_version()
    arch = normalize_deb_arch(arch)
    basename = f"{PKG_NAME}_{version}_{arch}"
    release_dir = DIST_DIR / "releases" / version
    release_dir.mkdir(parents=True, exist_ok=True)

    server_bin = None
    for candidate in (
        ROOT_DIR / "build" / "Release" / "kcp-proxy-server",
        ROOT_DIR / "build" / "kcp-proxy-server",
        ROOT_DIR / "bin" / "linux" / "kcp-proxy-server",
    ):
        if candidate.is_file():
            server_bin = candidate
            break
    if server_bin is None:
        raise PackageError(
            "Release kcp-proxy-server not found "
            "(looked in build/Release, build, bin/linux)"
        )

    templates = ROOT_DIR / "scripts" / "templates"
    refresh_service = templates / "kcp-proxy-server-key-refresh.service"
    refresh_timer = templates / "kcp-proxy-server-key-refresh.timer"
    for template in (refresh_service, refresh_timer):
        if not template.is_file():
            raise PackageError(f"missing systemd template: {template}")

    print(f"Packing {basename} with {server_bin} ...")
    stage = new_stage_dir(prefix=f"deb-{version}-")
    try:
        _stage_deb_tree(stage, server_bin, refresh_service, refresh_timer, version, arch)
        archive = release_dir / f"{basename}.deb"
        if shutil.which("dpkg-deb"):
            _deb_with_dpkg_deb(stage, archive)
        else:
            print("dpkg-deb not found; building the .deb with the standard library")
            _deb_with_stdlib(stage, archive)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    sums = update_sha256_sums(release_dir, archive)
    print(f"Built: {archive} ({archive.stat().st_size} bytes)")
    print(f"SHA256SUMS: {sums}")
    return archive


def _stage_deb_tree(stage, server_bin, refresh_service, refresh_timer, version, arch):
    debian = stage / "DEBIAN"
    debian.mkdir(parents=True, exist_ok=True)

    payload = {
        "./usr/local/bin/kcp-proxy/kcp-proxy-server": (server_bin, MODE_EXEC),
        "./etc/systemd/system/kcp-proxy-server-key-refresh.service": (refresh_service, MODE_FILE),
        "./etc/systemd/system/kcp-proxy-server-key-refresh.timer": (refresh_timer, MODE_FILE),
    }
    for arcname, (source, mode) in payload.items():
        copy_file(source, stage / arcname[2:], mode)

    write_text(
        stage / "usr/local/bin/kcp-proxy/kcp-proxy-server-wrapper.sh",
        WRAPPER_SH,
        MODE_EXEC,
    )
    write_text(stage / ENV_FILE.lstrip("/"), SERVER_ENV, MODE_SECRET)
    write_text(stage / "etc/systemd/system" / SERVICE_NAME, SYSTEMD_UNIT, MODE_FILE)

    control = (
        f"Package: {PKG_NAME}\n"
        f"Version: {version}\n"
        "Section: net\n"
        "Priority: optional\n"
        f"Architecture: {arch}\n"
        "Depends: systemd (>= 231), bash, libc6, libstdc++6\n"
        "Maintainer: dewei <860656812@qq.com>\n"
        "Description: KCP-based encrypted SOCKS5 proxy (server)\n"
        " SOCKS5 proxy that tunnels TCP traffic over an encrypted KCP (UDP) channel.\n"
        " This package installs and runs the remote server component as a systemd\n"
        " service. The daily session key is derived as YYYYMMDD (Beijing time) plus\n"
        " a configured suffix at each service (re)start.\n"
        "Homepage: https://github.com/dchen8525-dev/kcp-proxy-cpp\n"
    )
    write_text(debian / "control", control, MODE_FILE)
    # server.env is a conffile so upgrades preserve local modifications
    write_text(debian / "conffiles", f"{ENV_FILE}\n", MODE_FILE)
    write_text(debian / "postinst", DEB_POSTINST, MODE_EXEC)
    write_text(debian / "prerm", DEB_PRERM, MODE_EXEC)
    write_text(debian / "postrm", DEB_POSTRM, MODE_EXEC)
    write_text(debian / "md5sums", _deb_md5sums(stage), MODE_FILE)


def _deb_payload_entries(stage):
    """Yield (arcname, path) for every payload file outside DEBIAN, sorted."""
    for path in sorted(stage.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(stage)
        if relative.parts[0] == "DEBIAN":
            continue
        yield f"./{relative.as_posix()}", path


def _deb_mode(arcname: str) -> int:
    return DEB_MODES.get(arcname, MODE_FILE)


def _deb_md5sums(stage) -> str:
    lines = []
    for arcname, path in _deb_payload_entries(stage):
        digest = hashlib.md5(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {arcname[2:]}")
    return "\n".join(lines) + "\n"


def _deb_with_dpkg_deb(stage: Path, archive: Path) -> None:
    result = subprocess.run(
        ["dpkg-deb", "--build", "--root-owner-group", str(stage), str(archive)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise PackageError(f"dpkg-deb failed:\n{result.stderr.strip()}")


def _deb_directories(arcnames):
    """Parent directories, shallowest first so parents precede children."""
    seen = []
    for arcname in arcnames:
        parts = arcname[2:].split("/")[:-1]
        current = ""
        for part in parts:
            current = f"{current}/{part}" if current else part
            directory = f"./{current}"
            if directory not in seen:
                seen.append(directory)
    return sorted(seen, key=lambda d: d.count("/"))


def _deb_with_stdlib(stage: Path, archive: Path) -> None:
    """Build a .deb without dpkg-deb.

    Layout matches what dpkg-deb produces: `!<arch>` magic, then debian-binary,
    control.tar.gz and data.tar.xz.
    """
    control_buffer = io.BytesIO()
    with tarfile.open(fileobj=control_buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        # dpkg-deb emits a "./" entry first; keep the layout identical.
        tar.addfile(_tar_dir_info("."))
        for path in sorted((stage / "DEBIAN").iterdir()):
            if not path.is_file():
                continue
            data = path.read_bytes()
            info = tarfile.TarInfo(f"./{path.name}")
            info.size = len(data)
            info.mode = DEB_CONTROL_MODES.get(f"./{path.name}", MODE_FILE)
            info.mtime = 0
            info.type = tarfile.REGTYPE
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            tar.addfile(info, io.BytesIO(data))

    data_buffer = io.BytesIO()
    with tarfile.open(fileobj=data_buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        entries = list(_deb_payload_entries(stage))
        for arcname in _deb_directories(name for name, _ in entries):
            tar.addfile(_tar_dir_info(arcname))
        for arcname, path in entries:
            data = path.read_bytes()
            info = tarfile.TarInfo(arcname)
            info.size = len(data)
            info.mode = _deb_mode(arcname)
            info.mtime = 0
            info.type = tarfile.REGTYPE
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            tar.addfile(info, io.BytesIO(data))

    members = [
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", gzip.compress(control_buffer.getvalue(), mtime=0)),
        ("data.tar.xz", lzma.compress(data_buffer.getvalue(), format=lzma.FORMAT_XZ)),
    ]
    with archive.open("wb") as handle:
        handle.write(b"!<arch>\n")
        for name, data in members:
            handle.write(_ar_member(name, data))


def _ar_member(name: str, data: bytes, mtime: int = 0) -> bytes:
    """One ar archive member: 60-byte header + data padded to an even length."""
    header = (
        name.ljust(16)[:16].encode("ascii")
        + str(mtime).ljust(12)[:12].encode("ascii")
        + b"0".ljust(6)          # uid
        + b"0".ljust(6)          # gid
        + b"100644".ljust(8)     # mode
        + str(len(data)).ljust(10)[:10].encode("ascii")
        + b"`\n"                 # magic
    )
    if len(header) != 60:  # pragma: no cover - defensive
        raise PackageError(f"malformed ar header for {name}")
    return header + data + (b"\n" if len(data) % 2 else b"")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Build kcp-proxy release packages (stdlib only, cross-platform)."
    )
    # Defaults are set on the root parser so `package.py` with no subcommand
    # (alias for `standalone`) still exposes os/arch attributes.
    parser.set_defaults(os_name=None, arch=None)
    subparsers = parser.add_subparsers(dest="command")

    standalone = subparsers.add_parser(
        "standalone", help="CLI bundle (tar.gz on linux/macos, zip on windows)"
    )
    standalone.add_argument("--os", dest="os_name", default=None,
                            help="linux | macos | windows (default: auto-detect)")
    standalone.add_argument("--arch", default=None,
                            help="x64 | arm64 (default: auto-detect)")

    deb = subparsers.add_parser("deb", help="Debian package for the systemd service")
    deb.add_argument("--arch", default=None, help="amd64 | arm64 (default: dpkg query)")

    args = parser.parse_args(argv)
    command = args.command or "standalone"

    try:
        if command == "standalone":
            os_name = args.os_name or os.environ.get("KCP_PACKAGE_OS") or detect_os()
            if os_name not in ("linux", "macos", "windows"):
                raise PackageError(f"unsupported package OS: {os_name}")
            arch = args.arch or os.environ.get("KCP_PACKAGE_ARCH") or detect_arch()
            build_standalone(os_name, arch)
        elif command == "deb":
            build_deb(args.arch or os.environ.get("KCP_PACKAGE_ARCH"))
        else:  # pragma: no cover - argparse restricts the choices
            parser.error(f"unknown command: {command}")
    except PackageError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
