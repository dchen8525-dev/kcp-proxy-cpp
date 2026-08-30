#!/usr/bin/env bash
# KCP proxy shared configuration — canonical runtime configuration.
# Sourced by start.sh / install-service.sh / uninstall-service.sh.
# Parsed by deploy.py (keep KEY=VALUE lines simple: VAR="value" or VAR='value').

# ---------- default config ----------
# No production secret is checked into the repository. New installations must
# provide --suffix (or an equivalent secure input); existing server.env wins.
DEFAULT_SUFFIX=""
SERVER_PORT=8388
SERVER_HOST="0.0.0.0"
CLIENT_LISTEN_HOST="127.0.0.1"
CLIENT_LISTEN_PORT=1080
LOG_LEVEL="INFO"

# ---------- install paths (server side) ----------
INSTALL_DIR="/usr/local/bin/kcp-proxy"
ENV_DIR="/etc/kcp-proxy"
ENV_FILE="$ENV_DIR/server.env"
SERVICE_NAME="kcp-proxy-server.service"
SERVICE_USER="kcpproxy"

# ---------- key generation: UTC+8 YYYYMMDD + suffix ----------
# Suffix must be >= 8 chars so total key length >= 16 (min required by kcp-proxy).
key_date() {
    TZ=Asia/Shanghai date +%Y%m%d
}

make_key() {
    local suffix="$1"
    echo "$(key_date)${suffix}"
}

validate_suffix() {
    local suffix="$1"
    if [[ ! "$suffix" =~ ^[A-Za-z0-9._-]{8,128}$ ]]; then
        echo "Error: suffix must contain 8-128 letters, digits, '.', '_' or '-'" >&2
        return 1
    fi
}

check_key_len() {
    local key="$1"
    if [ ${#key} -lt 16 ]; then
        echo "Error: key length ${#key} < 16 (date=8 + suffix must be >= 8 chars)" >&2
        return 1
    fi
}
