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
# Server log file (stdout+stderr). Empty LOG_FILE in server.env = journald only.
LOG_FILE="/var/log/kcp-proxy/server.log"

# ---------- install paths (server side) ----------
INSTALL_DIR="/usr/local/bin/kcp-proxy"
ENV_DIR="/etc/kcp-proxy"
ENV_FILE="$ENV_DIR/server.env"
SERVICE_NAME="kcp-proxy-server.service"
SERVICE_USER="kcpproxy"

# ---------- kernel UDP buffer ceiling (server side) ----------
# The server asks for 4 MiB UDP socket buffers (UDP_SO_RCVBUF_BYTES /
# UDP_SO_SNDBUF_BYTES in src/kcp_proxy/config.hpp), but the kernel silently
# clamps those requests to net.core.rmem_max / net.core.wmem_max -- 208 KiB on a
# stock Debian host. setsockopt() still reports success, so the shortfall is
# invisible until a burst overflows the (much smaller) buffer, the kernel drops
# datagrams, and KCP misreads the drops as network loss and retransmits whole
# windows. install-service.sh raises the ceiling to these values, but only when
# the host's current value is lower: an operator who deliberately tuned rmem_max
# above this must never have it lowered by an install.
# Keep in sync with UDP_SO_RCVBUF_BYTES / UDP_SO_SNDBUF_BYTES in config.hpp --
# tests/smoke/smoke_test.py asserts the two agree.
SYSCTL_CONF="/etc/sysctl.d/99-kcp-proxy.conf"
UDP_RMEM_MAX=4194304
UDP_WMEM_MAX=4194304

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
