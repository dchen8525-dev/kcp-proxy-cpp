#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo " KCP Proxy Build (Linux/macOS)"
echo "========================================"

echo "[1/3] Setting up vcpkg..."
validate_vcpkg() {
    local root="$1"
    [ -x "$root/vcpkg" ] || { echo "Error: vcpkg executable not found at $root" >&2; exit 1; }
    local actual
    actual=$(git -C "$root" rev-parse HEAD 2>/dev/null || true)
    [ "$actual" = "$EXPECTED_VCPKG_COMMIT" ] || {
        echo "Error: vcpkg commit mismatch (expected $EXPECTED_VCPKG_COMMIT, got ${actual:-unknown})" >&2
        exit 1
    }
}

if [ -z "${VCPKG_ROOT:-}" ]; then
    if [ -x "$REPO_ROOT/vcpkg/vcpkg" ]; then
        VCPKG_ROOT="$REPO_ROOT/vcpkg"
    else
        echo "[1/3] Bootstrapping pinned vcpkg..."
        VCPKG_COMMIT="c5a15727ee70fddf0296f0d8aafc3f58916fefac"
        git clone https://github.com/microsoft/vcpkg.git "$REPO_ROOT/vcpkg"
        git -C "$REPO_ROOT/vcpkg" checkout --detach "$VCPKG_COMMIT"
        "$REPO_ROOT/vcpkg/bootstrap-vcpkg.sh" -disableMetrics
        VCPKG_ROOT="$REPO_ROOT/vcpkg"
    fi
else
    echo "[1/3] Using vcpkg at $VCPKG_ROOT"
fi
export VCPKG_ROOT

# Run a command in the background while showing a spinner + elapsed timer.
# Usage: with_spinner "label" command [args...]
with_spinner() {
    local label="$1"; shift
    local spinner='⣷⣯⣟⡿⢿⣻⣽⣾'

    "$@" &
    local pid=$!

    local start_ts=$(date +%s)
    local i=0

    while kill -0 "$pid" 2>/dev/null; do
        local elapsed=$(( $(date +%s) - start_ts ))
        local ci=$(( i % 8 ))
        printf "\r  %s ${spinner:ci:1} %ss" "$label" "$elapsed" >&2
        i=$(( i + 1 ))
        sleep 0.1
    done

    printf "\r  %s done (%ss)\n" "$label" "$(( $(date +%s) - start_ts ))" >&2

    wait "$pid"
}

echo "[2/3] Installing dependencies..."
case "$(uname -s):$(uname -m)" in
    Linux:x86_64) VCPKG_TRIPLET="x64-linux" ;;
    Darwin:x86_64) VCPKG_TRIPLET="x64-osx" ;;
    Darwin:arm64) VCPKG_TRIPLET="arm64-osx" ;;
    *) echo "Unsupported platform: $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac
with_spinner "Installing" "$VCPKG_ROOT/vcpkg" install --triplet="$VCPKG_TRIPLET"

echo "[3/3] Configuring and building..."

# Keep existing CMake caches and IDE state; use `rm -rf build` explicitly
# when a clean configure is required.
cmake --preset default
cmake --build --preset release --parallel

echo
OUTDIR="$REPO_ROOT/bin/linux"
mkdir -p "$OUTDIR"
cp -f "$REPO_ROOT/build/kcp-proxy-server" "$OUTDIR/"
cp -f "$REPO_ROOT/build/kcp-proxy-client" "$OUTDIR/"
ls -lh "$OUTDIR/"
echo
echo "Done. Output: $OUTDIR  (binaries only; deploy scripts live in scripts/)"
echo "Deploy: ./deploy.sh user@server-host"
