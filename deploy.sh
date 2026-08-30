#!/usr/bin/env bash
# Thin forwarder → scripts/deploy/deploy.py (Python3, cross-platform)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Under Git Bash/MSYS, `pwd` yields a POSIX path (/d/work/...). A native Windows
# Python resolves that relative to the current drive (d:\d\work\...), so convert
# to a Windows path before handing it over.
if command -v cygpath >/dev/null 2>&1; then
    SCRIPT_DIR="$(cygpath -w "$SCRIPT_DIR")"
fi

DEPLOY_PY="$SCRIPT_DIR/scripts/deploy/deploy.py"

if [ ! -f "$DEPLOY_PY" ]; then
    echo "Error: deploy script not found at $DEPLOY_PY" >&2
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    exec python3 "$DEPLOY_PY" "$@"
elif command -v python >/dev/null 2>&1; then
    exec python "$DEPLOY_PY" "$@"
else
    echo "Error: python3 not found. Install Python 3 or run scripts/deploy/deploy.py directly." >&2
    exit 1
fi
