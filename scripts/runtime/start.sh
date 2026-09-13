#!/usr/bin/env bash
# Local runtime launcher: run the server or the client straight from a checkout
# (or from an unpacked release, where this script sits next to the binaries).
#
# Usage:
#   scripts/runtime/start.sh server [suffix]        # UDP listener on SERVER_PORT
#   scripts/runtime/start.sh client HOST [suffix]    # SOCKS5 on CLIENT_LISTEN_PORT
#
# The key is derived as YYYYMMDD (Beijing time) + suffix -- the same scheme
# install-service.sh put on the server and the GUI derives locally -- so a
# server and a client started from the same suffix share today's key.
#
# The key is handed over through KCP_PROXY_KEY, not -k: a process command line
# is readable by every local user, the environment only by the same user.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration comes from common.sh (repo checkout or package); the built-in
# fallback mirrors it so the script still works if that file is missing.
if [ -f "$SCRIPT_DIR/common.sh" ]; then
    # shellcheck source=common.sh
    source "$SCRIPT_DIR/common.sh"
else
    SERVER_PORT=8388
    SERVER_HOST="0.0.0.0"
    CLIENT_LISTEN_HOST="127.0.0.1"
    CLIENT_LISTEN_PORT=1080
    LOG_LEVEL="INFO"
    DEFAULT_SUFFIX=""
    key_date() { TZ=Asia/Shanghai date +%Y%m%d; }
    make_key() { echo "$(key_date)$1"; }
    validate_suffix() {
        if [ "${#1}" -lt 8 ] || [ "${#1}" -gt 128 ] ||
           printf '%s' "$1" | grep -q '[^A-Za-z0-9._-]'; then
            echo "Error: suffix must be 8-128 chars of [A-Za-z0-9._-]" >&2
            return 1
        fi
    }
fi

usage() {
    echo "Usage: $0 server [suffix]" >&2
    echo "       $0 client HOST [suffix]" >&2
    echo "  suffix: 8-128 chars of [A-Za-z0-9._-]; the key is Beijing date + suffix" >&2
}

# Locate a built binary. Covers the release layout (next to this script), the
# bin/<os> output of build.sh / build_vs.bat, and a local CMake build tree.
# Both the bare and the .exe name are tried so this works under Git Bash too.
find_binary() {
    local name="$1" dir candidate
    for dir in \
        "$SCRIPT_DIR" \
        "$SCRIPT_DIR/.." \
        "$SCRIPT_DIR/../../bin/linux" \
        "$SCRIPT_DIR/../../bin/macos" \
        "$SCRIPT_DIR/../../bin/windows" \
        "$SCRIPT_DIR/../../build" \
        "$SCRIPT_DIR/../../build/Release"; do
        for candidate in "$dir/$name" "$dir/$name.exe"; do
            if [ -x "$candidate" ]; then
                echo "$candidate"
                return 0
            fi
        done
    done
    echo "Error: $name not found; build first (./build.sh) or unpack a release" >&2
    return 1
}

MODE="${1:-}"
[ -n "$MODE" ] || { usage; exit 1; }
shift

case "$MODE" in
    server)
        SUFFIX="${1:-${DEFAULT_SUFFIX:-}}"
        validate_suffix "$SUFFIX"
        BIN="$(find_binary kcp-proxy-server)"
        export KCP_PROXY_KEY="$(make_key "$SUFFIX")"
        echo "Starting server: UDP ${SERVER_HOST}:${SERVER_PORT} (key date + suffix)" >&2
        exec "$BIN" -p "$SERVER_PORT" -H "$SERVER_HOST" -L "$LOG_LEVEL"
        ;;
    client)
        HOST="${1:-}"
        SUFFIX="${2:-${DEFAULT_SUFFIX:-}}"
        if [ -z "$HOST" ]; then
            usage
            exit 1
        fi
        validate_suffix "$SUFFIX"
        BIN="$(find_binary kcp-proxy-client)"
        export KCP_PROXY_KEY="$(make_key "$SUFFIX")"
        echo "Starting client: server=${HOST}:${SERVER_PORT} socks5=${CLIENT_LISTEN_HOST}:${CLIENT_LISTEN_PORT}" >&2
        exec "$BIN" -s "$HOST" -p "$SERVER_PORT" \
            -H "$CLIENT_LISTEN_HOST" -l "$CLIENT_LISTEN_PORT" -L "$LOG_LEVEL"
        ;;
    *)
        usage
        exit 1
        ;;
esac
