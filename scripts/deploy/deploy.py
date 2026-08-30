#!/usr/bin/env python3
"""
One-command remote deployment for kcp-proxy-server.

Works on Windows / Linux / macOS — stdlib only. Requires the system
OpenSSH client (ssh/scp), which is built into Windows 10+ and
available on virtually every Linux/macOS machine.

Usage:
    python3 scripts/deploy.py user@host [-P ssh-port] [-i identity-file]
                                        [--suffix SUFFIX] [--uninstall]
                                        [--dry-run] [--verbose]

Examples:
    python3 scripts/deploy.py root@1.2.3.4
    python3 scripts/deploy.py ubuntu@example.com -P 2222 -i ~/.ssh/id_ed25519
    python3 scripts/deploy.py root@1.2.3.4 --suffix 'MyS3cret!'
    python3 scripts/deploy.py root@1.2.3.4 --uninstall
    python3 scripts/deploy.py root@1.2.3.4 --dry-run  # verify package without connecting
"""

import argparse
import datetime
import getpass
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

# Exit codes
EXIT_CONFIG_ERROR = 1
EXIT_BINARY_MISSING = 2
EXIT_SSH_ERROR = 3
EXIT_PACKAGING_ERROR = 4

# Global verbose level (set in main())
_verbose = 0

ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin" / "linux"
COMMON_SH = ROOT_DIR / "scripts" / "runtime" / "common.sh"

# Remote staging is allocated per deployment by the remote shell.
REMOTE_BASE = "/var/tmp"

# Files shipped to the server: (local path, remote name, mode)
PACKAGE_FILES = [
    (BIN_DIR / "kcp-proxy-server", "kcp-proxy-server", 0o755),
    (ROOT_DIR / "scripts" / "deploy" / "install-service.sh", "install-service.sh", 0o755),
    (ROOT_DIR / "scripts" / "deploy" / "uninstall-service.sh", "uninstall-service.sh", 0o755),
    (COMMON_SH, "common.sh", 0o644),
]


def die(msg, code=1):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(code)


def load_common_defaults():
    """Parse simple VAR=value lines from scripts/common.sh."""
    defaults = {}
    if not COMMON_SH.is_file():
        return defaults
    pattern = re.compile(r"""^([A-Z_]+)=["']?(.*?)["']?$""")
    for line in COMMON_SH.read_text(encoding="utf-8").splitlines():
        m = pattern.match(line.strip())
        if m:
            defaults[m.group(1)] = m.group(2)
    return defaults


def check_tools():
    for tool in ("ssh", "scp"):
        if not shutil.which(tool):
            die(f"'{tool}' not found in PATH. On Windows, enable the "
                f"OpenSSH Client optional feature; on Linux/macOS install openssh-client.",
                EXIT_CONFIG_ERROR)


def validate_suffix(suffix):
    if not re.fullmatch(r"[A-Za-z0-9._-]{8,128}", suffix or ""):
        die("suffix must contain 8-128 letters, digits, '.', '_' or '-'", EXIT_CONFIG_ERROR)


def validate_tar_members(path):
    with tarfile.open(path, "r:gz") as tar:
        for member in tar.getmembers():
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts:
                die(f"unsafe archive member: {member.name}", EXIT_PACKAGING_ERROR)
            if member.issym() or member.islnk():
                die(f"links are not allowed in deployment archive: {member.name}", EXIT_PACKAGING_ERROR)


def package_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
def check_binaries():
    missing = [str(p) for p, _, _ in PACKAGE_FILES if not p.is_file()]
    if missing:
        die("required files missing:\n  " + "\n  ".join(missing) +
            "\nBuild the Linux server binary first (./build.sh copies it to bin/linux/).",
            EXIT_BINARY_MISSING)


def build_package(dest):
    """Create tar.gz with fixed modes (Windows has no exec bits)."""
    with tarfile.open(dest, "w:gz") as tar:
        for local, name, mode in PACKAGE_FILES:
            info = tar.gettarinfo(str(local), arcname=name)
            info.mode = mode
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            with open(local, "rb") as f:
                tar.addfile(info, f)


def run(cmd, env=None, **kwargs):
    if _verbose > 0:
        print("+ " + " ".join(str(c) for c in cmd))
    result = subprocess.run(cmd, env=env, **kwargs)
    if result.returncode != 0:
        die(f"command failed with exit code {result.returncode}", EXIT_SSH_ERROR)


def ssh_opts(args, prefix="ssh"):
    """Port/identity options; scp uses -P for port, ssh uses -p."""
    cmd = []
    if args.port:
        cmd += ["-P" if prefix == "scp" else "-p", str(args.port)]
    if args.identity:
        cmd += ["-i", args.identity]
    return cmd


def probe_passwordless(args):
    """True if key/agent auth already works without any prompt."""
    cmd = (["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"] +
           ssh_opts(args) + [args.target, "true"])
    return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def setup_askpass(tmpdir, password):
    """Write an SSH_ASKPASS helper so scp+ssh reuse one typed password.

    The helper prints the password from a sibling file (avoids quoting
    issues with special characters in passwords). Returns env overrides.
    """
    pw = Path(tmpdir) / "askpass-pw.txt"
    pw.write_text(password + "\n", encoding="utf-8")
    if os.name == "nt":
        helper = Path(tmpdir) / "askpass.bat"
        # CRLF line endings required for cmd.exe batch parsing
        helper.write_text(f'@echo off\r\ntype "{pw}"\r\n', encoding="ascii")
    else:
        helper = Path(tmpdir) / "askpass.sh"
        helper.write_text(f'#!/bin/sh\ncat "{pw}"\n', encoding="ascii")
        helper.chmod(0o700)
        pw.chmod(0o600)
    return {
        **os.environ,
        "SSH_ASKPASS": str(helper),
        "SSH_ASKPASS_REQUIRE": "force",
        # Pre-8.4 OpenSSH only consults askpass when DISPLAY is set
        "DISPLAY": os.environ.get("DISPLAY", "kcp-proxy-deploy"),
    }


def ssh_cmd(args):
    return ["ssh", "-t"] + ssh_opts(args) + [args.target]


def scp_cmd(args):
    return ["scp"] + ssh_opts(args, prefix="scp")


def beijing_today():
    tz = datetime.timezone(datetime.timedelta(hours=8))
    return datetime.datetime.now(tz).strftime("%Y%m%d")


def main():
    global PACKAGE_FILES
    parser = argparse.ArgumentParser(
        description="Deploy kcp-proxy-server to a remote Linux host over SSH.")
    parser.add_argument("target", help="SSH target, e.g. root@1.2.3.4")
    parser.add_argument("-P", "--port", type=int, help="SSH port (default 22)")
    parser.add_argument("-i", "--identity", help="SSH identity (private key) file")
    parser.add_argument("--suffix",
                        help="key suffix stored on the server; omit to keep the "
                             "existing one (or the built-in default on first install)")
    parser.add_argument("--uninstall", action="store_true",
                        help="remove the service and all files from the server")
    parser.add_argument("--dry-run", action="store_true",
                        help="build and show the package contents without connecting")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="increase verbosity (show ssh/scp commands)")
    args = parser.parse_args()

    # Store verbose level globally for run()
    global _verbose
    _verbose = args.verbose

    # Dry-run is entirely local: do not inspect SSH or prompt for credentials.
    defaults = load_common_defaults()
    if args.suffix:
        validate_suffix(args.suffix)

    if args.dry_run:
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "kcp-proxy-deploy.tar.gz"
            if args.uninstall:
                PACKAGE_FILES = [f for f in PACKAGE_FILES
                                 if f[1] in ("uninstall-service.sh", "common.sh")]
            else:
                check_binaries()
            build_package(pkg)
            validate_tar_members(pkg)
            print("Dry-run package contents:")
            with tarfile.open(pkg, "r:gz") as tar:
                for member in tar.getmembers():
                    print(f"  {oct(member.mode)} {member.name:24} {member.size:>8} bytes")
            print(f"SHA256: {package_sha256(pkg)}")
        return

    check_tools()

    password = None
    if args.identity:
        pass  # explicit key auth; ssh uses it directly
    elif probe_passwordless(args):
        print("Passwordless SSH auth OK (key/agent).")
    else:
        password = getpass.getpass(
            f"SSH password for {args.target} (asked once, input hidden): ")
        if not password:
            password = None
            print("No password given — falling back to interactive prompts "
                  "(you may be asked more than once).")

    with tempfile.TemporaryDirectory() as tmp:
        # helper files land in this temp dir and are auto-deleted on exit
        run_env = setup_askpass(tmp, password) if password else None

        pkg = Path(tmp) / "kcp-proxy-deploy.tar.gz"

        if args.uninstall:
            # Only the uninstall script (+ common.sh) is needed
            PACKAGE_FILES = [f for f in PACKAGE_FILES
                             if f[1] in ("uninstall-service.sh", "common.sh")]
            for local, _, _ in PACKAGE_FILES:
                if not local.is_file():
                    die(f"required file missing: {local}")
        else:
            check_binaries()

        print(f"Building package {pkg.name} ...")
        build_package(pkg)
        validate_tar_members(pkg)

        checksum = package_sha256(pkg)
        upload_name = f"/var/tmp/kcp-proxy-upload-{secrets.token_hex(8)}.tar.gz"
        print(f"\nUploading to {args.target} ...")
        run(scp_cmd(args) + [str(pkg), f"{args.target}:{upload_name}"], env=run_env)

        print("\nInstalling on remote host ...")
        remote = (
            "set -eu; "
            "stage=$(mktemp -d /var/tmp/kcp-proxy-deploy.XXXXXX); chmod 700 \"$stage\"; "
            "pkg=\"$stage/package.tar.gz\"; "
            "trap 'rm -rf \"$stage\" " + shlex.quote(upload_name) + "' EXIT; "
            "mv " + shlex.quote(upload_name) + " \"$pkg\"; "
            "printf '%s  %s\\n' " + shlex.quote(checksum) + " \"$pkg\" | sha256sum -c -; "
            "tar xzf \"$pkg\" -C \"$stage\"; "
            "cd \"$stage\"; "
        )
        if args.uninstall:
            remote += "sudo ./uninstall-service.sh"
        else:
            suffix_arg = ""
            if args.suffix:
                # Pass only validated values; avoid shell injection.
                suffix_arg = f" {shlex.quote(args.suffix)}"
            remote += f"sudo ./install-service.sh{suffix_arg}"
        # -t gives sudo a tty in case it needs to prompt for a password
        run(ssh_cmd(args) + [remote], env=run_env)

    if not args.uninstall:
        suffix = args.suffix or "<configured-on-server>"
        port = defaults.get("SERVER_PORT", "8388")
        listen_host = defaults.get("CLIENT_LISTEN_HOST", "127.0.0.1")
        listen_port = defaults.get("CLIENT_LISTEN_PORT", "1080")
        host = args.target.split("@")[-1]
        print("\n" + "=" * 60)
        print("Deployment complete.")
        print(f"  Today's key: {beijing_today()}<suffix>  (Beijing date + suffix)")
        print(f"  Server port: {port}/udp")
        print()
        print("Connect a client:")
        print(f"  scripts/start.sh client {host} '{suffix}'")
        print(f"  scripts\\start.bat client {host} \"{suffix}\"")
        print(f"Then point your app at SOCKS5 {listen_host}:{listen_port}.")
        print()
        print("NOTE: the key is re-derived from the Beijing date on every")
        print("service (re)start, and a cron job restarts the service every")
        print("6 hours. After a restart crosses midnight, restart your client.")
        print("=" * 60)


if __name__ == "__main__":
    main()
