#!/usr/bin/env python3
"""Smoke tests for packaging/deployment invariants (stdlib only)."""
from pathlib import Path
import json
import re
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def test_paths_and_secrets():
    package = (ROOT / "scripts/package/package.sh").read_text(encoding="utf-8")
    assert 'dirname "${BASH_SOURCE[0]}"' in package
    assert '/..' in package
    common = (ROOT / "scripts/runtime/common.sh").read_text(encoding="utf-8")
    assert "Kcp$Pr0xy!2024#Sec" not in common
    assert (ROOT / "scripts/deploy/deploy.py").exists()
    assert (ROOT / "scripts/package/package.sh").exists()
    deploy = (ROOT / "scripts/deploy/deploy.py").read_text(encoding="utf-8")
    assert "/tmp/kcp-proxy-deploy\"" not in deploy
    assert "mktemp -d /var/tmp/kcp-proxy-deploy" in deploy
    gui = (ROOT / "gui/electron/main.js").read_text(encoding="utf-8")
    assert "args.join(' ')" not in gui
    assert "-k <" not in gui
    assert "electron-builder.win.json" in (ROOT / "gui/electron/package.json").read_text(encoding="utf-8")
    service = (ROOT / "scripts/deploy/install-service.sh").read_text(encoding="utf-8")
    assert "kcp-proxy-server-key-refresh.timer" in service
    uninstall = (ROOT / "scripts/deploy/uninstall-service.sh").read_text(encoding="utf-8")
    assert "--purge" in uninstall


def test_vcpkg_and_presets():
    # build.sh pins the vcpkg checkout commit; vcpkg.json's builtin-baseline
    # must agree so manifest resolution uses the same upstream state.
    build = (ROOT / "build.sh").read_text(encoding="utf-8")
    match = re.search(r'VCPKG_COMMIT="([0-9a-f]{40})"', build)
    assert match, 'build.sh must pin a vcpkg commit (VCPKG_COMMIT="<40-hex>")'
    commit = match.group(1)
    manifest = json.loads((ROOT / "vcpkg.json").read_text(encoding="utf-8"))
    assert manifest["builtin-baseline"] == commit
    json.loads((ROOT / "CMakePresets.json").read_text(encoding="utf-8"))


def test_suffix_vectors():
    pattern = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
    for value in ("abcdefgh", "abc_1234", "release-2026"):
        assert pattern.fullmatch(value)
    for value in ("", "short", "abc def", "abc=1234", "abc\n1234"):
        assert not pattern.fullmatch(value)


def test_archive_members():
    for archive in (ROOT / "dist").glob("**/*.tar.gz"):
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar.getmembers():
                path = Path(member.name)
                assert not path.is_absolute()
                assert ".." not in path.parts
                assert not (member.issym() or member.islnk())


if __name__ == "__main__":
    test_paths_and_secrets()
    test_vcpkg_and_presets()
    test_suffix_vectors()
    test_archive_members()
    print("smoke tests passed")
