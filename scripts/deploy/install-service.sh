#!/usr/bin/env bash
# Install kcp-proxy-server as a systemd service (self-contained).
#
# Usage:
#   sudo ./install-service.sh [suffix]
#
# Layout: this script expects the kcp-proxy-server binary next to itself
# (deploy package), or in ../bin/linux (repo checkout). kcp-proxy-client is
# installed too when present, but is never required: the deploy package ships
# only the server.
# common.sh next to this script (deploy package) or in ../runtime (repo
# checkout) provides defaults; built-in defaults are used as fallback.
#
# The suffix is stored in /etc/kcp-proxy/server.env (not on the command
# line, not in the unit name). The service wrapper derives the daily key
# as YYYYMMDD + suffix (Beijing time) at each (re)start.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------- config: common.sh if available, else built-in defaults ----------
# Deploy package: common.sh is shipped next to this script. Repo checkout: it
# lives in ../runtime/. The old ../../scripts/common.sh fallback never existed,
# so the deploy package silently ignored the common.sh it had just shipped and
# used the built-in defaults instead.
if [ -f "$SCRIPT_DIR/common.sh" ]; then
    source "$SCRIPT_DIR/common.sh"
elif [ -f "$SCRIPT_DIR/../runtime/common.sh" ]; then
    source "$SCRIPT_DIR/../runtime/common.sh"
else
    DEFAULT_SUFFIX=""
    SERVER_PORT=8388
    SERVER_HOST="0.0.0.0"
    LOG_LEVEL="INFO"
    LOG_FILE="/var/log/kcp-proxy/server.log"
    INSTALL_DIR="/usr/local/bin/kcp-proxy"
    ENV_DIR="/etc/kcp-proxy"
    ENV_FILE="$ENV_DIR/server.env"
    SERVICE_NAME="kcp-proxy-server.service"
    SERVICE_USER="kcpproxy"
    SYSCTL_CONF="/etc/sysctl.d/99-kcp-proxy.conf"
    UDP_RMEM_MAX=4194304
    UDP_WMEM_MAX=4194304
fi

# Serialize concurrent installs when flock is available.
if command -v flock >/dev/null 2>&1; then
    exec 9>/run/kcp-proxy-install.lock
    flock -n 9 || { echo "Another kcp-proxy installation is running" >&2; exit 1; }
fi

# ---------- root check ----------
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (try: sudo $0 $*)" >&2
    exit 1
fi

# ---------- locate binaries ----------
if [ -f "$SCRIPT_DIR/kcp-proxy-server" ]; then
    SRC_BIN_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../bin/linux/kcp-proxy-server" ]; then
    SRC_BIN_DIR="$SCRIPT_DIR/../bin/linux"
else
    echo "Error: kcp-proxy-server binary not found next to this script or in ../bin/linux" >&2
    exit 1
fi

# ---------- suffix: arg > existing env file > required on first install ----------
SUFFIX=""
if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    SUFFIX="$1"
elif [ -f "$ENV_FILE" ]; then
    # Reinstall without args: keep the previously configured suffix
    SUFFIX=$(grep -E '^SUFFIX=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true)
fi
if [ -z "$SUFFIX" ]; then
    echo "Error: no suffix configured. Pass a suffix of at least 8 safe characters." >&2
    exit 1
fi
validate_suffix "$SUFFIX"
KEY_LEN=$((8 + ${#SUFFIX}))
check_key_len "$(printf '%*s' "$KEY_LEN" '' | tr ' ' x)"

# ---------- log file: existing env file wins, else default ----------
# The service can only write under /var/log/kcp-proxy (ReadWritePaths in the
# unit, and chown must stay scoped to that directory), so enforce it here.
LOG_FILE=""
if [ -f "$ENV_FILE" ]; then
    LOG_FILE=$(grep -E '^LOG_FILE=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true)
fi
case "$LOG_FILE" in
    /var/log/kcp-proxy/*) ;;
    "")
        LOG_FILE="/var/log/kcp-proxy/server.log" ;;
    *)
        echo "Warning: LOG_FILE must stay under /var/log/kcp-proxy (the only" >&2
        echo "directory the service can write); using the default instead." >&2
        LOG_FILE="/var/log/kcp-proxy/server.log" ;;
esac
LOG_DIR=$(dirname "$LOG_FILE")

# ---------- migrate from legacy @template unit, if present ----------
if [ -f /etc/systemd/system/kcp-proxy-server@.service ]; then
    echo "Found legacy kcp-proxy-server@.service — migrating to $SERVICE_NAME ..."
    for unit in $(systemctl list-units --type=service --all 'kcp-proxy-server@*.service' --no-legend | awk '{print $1}'); do
        systemctl stop "$unit" || true
        systemctl disable "$unit" || true
    done
    rm -f /etc/systemd/system/kcp-proxy-server@.service
fi

# ---------- service user ----------
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating system user: $SERVICE_USER"
    useradd --system --no-create-home --shell /sbin/nologin "$SERVICE_USER"
fi

# ---------- install binaries ----------
echo "Installing binaries to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp -f "$SRC_BIN_DIR/kcp-proxy-server" "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR/kcp-proxy-server"
# The client is optional. A server-only deploy package ships just the server,
# and an unconditional `cp` here aborted the entire install under `set -e`
# before the service was ever created. Install it only when it is present.
if [ -f "$SRC_BIN_DIR/kcp-proxy-client" ]; then
    cp -f "$SRC_BIN_DIR/kcp-proxy-client" "$INSTALL_DIR/"
    chmod 755 "$INSTALL_DIR/kcp-proxy-client"
fi

# ---------- env file (suffix lives here, mode 600) ----------
echo "Writing $ENV_FILE ..."
mkdir -p "$ENV_DIR"
tmp_env=$(mktemp "$ENV_DIR/server.env.XXXXXX")
chmod 600 "$tmp_env"
cat > "$tmp_env" << EOF
# kcp-proxy-server configuration
# Daily key = YYYYMMDD (Beijing time) + SUFFIX. Changes take effect on restart.
SUFFIX=$SUFFIX
PORT=$SERVER_PORT
HOST=$SERVER_HOST
LOG_LEVEL=$LOG_LEVEL
# Server log file (stdout+stderr). Empty = log to journald only.
# Must stay under /var/log/kcp-proxy unless you also extend ReadWritePaths
# in the systemd unit (ProtectSystem=strict blocks everything else).
LOG_FILE=$LOG_FILE
EOF
mv -f "$tmp_env" "$ENV_FILE"
chmod 600 "$ENV_FILE"

# ---------- log directory (parent of LOG_FILE, writable by the service user) ----------
echo "Preparing log directory: $LOG_DIR ..."
mkdir -p "$LOG_DIR"
chown "$SERVICE_USER" "$LOG_DIR"
chmod 755 "$LOG_DIR"

# ---------- wrapper (derives daily key, never logs the full key) ----------
cat > "$INSTALL_DIR/kcp-proxy-server-wrapper.sh" << 'WRAPPER'
#!/usr/bin/env bash
# Wrapper: derives daily key = YYYYMMDD (Beijing time) + SUFFIX.
# SUFFIX/PORT/HOST/LOG_LEVEL/LOG_FILE come from EnvironmentFile=/etc/kcp-proxy/server.env
set -euo pipefail

SUFFIX="${SUFFIX:?SUFFIX not set — check /etc/kcp-proxy/server.env}"
PORT="${PORT:-8388}"
HOST="${HOST:-0.0.0.0}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
# Empty LOG_FILE = log to journald only. Otherwise stdout+stderr are appended
# to the file. The key-refresh timer restarts the service every 6h, so the
# 10 MiB rotation below runs every 6h and keeps one .1 generation.
LOG_FILE="${LOG_FILE:-}"
SERVER_BIN=/usr/local/bin/kcp-proxy/kcp-proxy-server

DATE_BEIJING=$(TZ=Asia/Shanghai date +%Y%m%d)
KEY="${DATE_BEIJING}${SUFFIX}"

# Never log the full key — only the date portion and suffix length.
echo "Starting kcp-proxy-server  key_date=${DATE_BEIJING}  suffix_len=${#SUFFIX}  port=${PORT}"

# Probe writability in a subshell: a failed redirection on a special builtin
# would abort the wrapper, but here it just fails the probe.
if [ -n "$LOG_FILE" ] && ( : >> "$LOG_FILE" ) 2>/dev/null; then
    if [ -f "$LOG_FILE" ]; then
        size=$(wc -c < "$LOG_FILE" 2>/dev/null | tr -d ' \t' || echo 0)
        if [ "$size" -gt 10485760 ]; then
            mv -f "$LOG_FILE" "$LOG_FILE.1"
        fi
    fi
    {
        echo "=== $(TZ=Asia/Shanghai date '+%F %T') starting  key_date=${DATE_BEIJING}  port=${PORT} ==="
        exec "$SERVER_BIN" -k "$KEY" -p "$PORT" -H "$HOST" -L "$LOG_LEVEL"
    } >> "$LOG_FILE" 2>&1
fi

if [ -n "$LOG_FILE" ]; then
    echo "WARNING: LOG_FILE=$LOG_FILE is not writable — logging to journald instead" >&2
fi
exec "$SERVER_BIN" -k "$KEY" -p "$PORT" -H "$HOST" -L "$LOG_LEVEL"
WRAPPER
chmod 755 "$INSTALL_DIR/kcp-proxy-server-wrapper.sh"

# ---------- systemd unit (fixed name, no @template) ----------
cat > "/etc/systemd/system/$SERVICE_NAME" << EOF
[Unit]
Description=KCP Proxy Server
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/dchen8525-dev/kcp-proxy-cpp
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=$SERVICE_USER
EnvironmentFile=-$ENV_FILE
ExecStart=$INSTALL_DIR/kcp-proxy-server-wrapper.sh
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
# Allow writes to LOG_FILE's directory (see server.env); '-' = optional path
ReadWritePaths=-$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

# ---------- kernel UDP buffer ceiling (must precede the restart) ----------
# The server requests 4 MiB socket buffers when it starts, and the kernel clamps
# them to net.core.rmem_max / net.core.wmem_max without reporting an error. The
# ceiling therefore has to be raised BEFORE the service starts: raising it
# afterwards would leave the running process holding the clamped buffer until
# the next restart.
#
# Only ever raise. A host already at or above the required values is left
# completely untouched -- no file is written at all -- so an operator's own
# sysctl tuning is never overwritten, and a key that is already high enough is
# omitted from the drop-in rather than written back down to our value.
#
# sysctl is not guaranteed to exist on a minimal Debian host, and a failure here
# is not fatal: the service still runs, just with smaller buffers and a WARNING
# in its log naming the clamped value (see describe_buffer_clamp in the server).
apply_udp_buffer_ceiling() {
    if ! command -v sysctl >/dev/null 2>&1; then
        echo "Warning: sysctl not found; leaving the kernel UDP buffer ceiling alone."
        echo "         The server will log a WARNING if the kernel clamps its buffers."
        return 0
    fi

    cur_rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
    cur_wmem=$(sysctl -n net.core.wmem_max 2>/dev/null || echo 0)
    # A missing/odd value must not turn into an arithmetic error under set -e.
    case "$cur_rmem" in ''|*[!0-9]*) cur_rmem=0 ;; esac
    case "$cur_wmem" in ''|*[!0-9]*) cur_wmem=0 ;; esac

    if [ "$cur_rmem" -ge "$UDP_RMEM_MAX" ] && [ "$cur_wmem" -ge "$UDP_WMEM_MAX" ]; then
        echo "UDP buffer ceiling already sufficient (rmem_max=$cur_rmem wmem_max=$cur_wmem); not touching it."
        return 0
    fi

    # Report only the keys actually being raised. A single "rmem_max 8388608 ->
    # 4194304" line would be a lie: an already-sufficient key is never lowered,
    # it is simply left out of the drop-in.
    raise_msg=""
    if [ "$cur_rmem" -lt "$UDP_RMEM_MAX" ]; then
        raise_msg="rmem_max $cur_rmem -> $UDP_RMEM_MAX"
    fi
    if [ "$cur_wmem" -lt "$UDP_WMEM_MAX" ]; then
        if [ -n "$raise_msg" ]; then raise_msg="$raise_msg, "; fi
        raise_msg="${raise_msg}wmem_max $cur_wmem -> $UDP_WMEM_MAX"
    fi
    echo "Raising UDP buffer ceiling: $raise_msg"
    mkdir -p "$(dirname "$SYSCTL_CONF")"
    {
        echo "# Written by kcp-proxy install-service.sh. See CLAUDE.md (Deployment)."
        echo "# The kcp-proxy server asks for 4 MiB UDP socket buffers. Without this"
        echo "# ceiling the kernel silently clamps them to the defaults (208 KiB on"
        echo "# Debian), then drops datagrams under burst -- which KCP misreads as"
        echo "# network loss and answers with whole-window retransmission."
        echo "# Only the keys that were below the required value are listed, so a"
        echo "# host already tuned higher keeps its own setting."
        # Written as if-blocks, not `[ ... ] && echo`: the latter returns 1 when
        # the test is false, and under `set -e` a false trailing test would
        # abort the whole install whenever only one of the two keys needed raising.
        if [ "$cur_rmem" -lt "$UDP_RMEM_MAX" ]; then echo "net.core.rmem_max=$UDP_RMEM_MAX"; fi
        if [ "$cur_wmem" -lt "$UDP_WMEM_MAX" ]; then echo "net.core.wmem_max=$UDP_WMEM_MAX"; fi
    } > "$SYSCTL_CONF"
    chmod 644 "$SYSCTL_CONF"

    # Apply just this file: 'sysctl --system' would also re-read every other
    # drop-in on the host, turning someone else's broken file into our failure.
    if sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1; then
        echo "  now: rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null || echo '?') wmem_max=$(sysctl -n net.core.wmem_max 2>/dev/null || echo '?')"
    else
        echo "Warning: could not apply $SYSCTL_CONF." >&2
        echo "         The server will log a WARNING naming the clamped buffer size." >&2
    fi
}
apply_udp_buffer_ceiling

# ---------- enable & (re)start ----------
systemctl daemon-reload
echo "Enabling and starting $SERVICE_NAME ..."
systemctl enable "$SERVICE_NAME" >/dev/null
systemctl restart "$SERVICE_NAME"

# ---------- systemd timer: refresh the daily key at 00/06/12/18 local ----------
TIMER_SERVICE="kcp-proxy-server-key-refresh.service"
TIMER_UNIT="kcp-proxy-server-key-refresh.timer"
cat > "/etc/systemd/system/$TIMER_SERVICE" << 'EOF'
[Unit]
Description=Refresh KCP proxy daily key
After=kcp-proxy-server.service

[Service]
Type=oneshot
ExecStart=/bin/systemctl restart kcp-proxy-server.service
EOF
cat > "/etc/systemd/system/$TIMER_UNIT" << 'EOF'
[Unit]
Description=Refresh KCP proxy daily key (restart server at 00/06/12/18 local)

[Timer]
# Calendar schedule, deliberately NOT OnBootSec/OnUnitActiveSec. A monotonic
# elapse whose time has already passed when the timer is (re)started is dropped
# by systemd (Persistent= only applies to OnCalendar=), leaving the timer
# "active (elapsed)" with no next trigger. The server then keeps whatever
# Beijing-date key it started with, so every client fails DECRYPT_FAILED until
# someone restarts the service by hand.
# 0/6:00 = 00:00, 06:00, 12:00, 18:00 local, so the key follows the Beijing
# date change within a second instead of up to six hours later.
OnCalendar=*-*-* 0/6:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now "$TIMER_UNIT"

# Verify the timer actually armed: an empty next-elapse means it will never fire
# again and the daily key would silently freeze.
TIMER_NEXT=$(systemctl show "$TIMER_UNIT" -p NextElapseUSecRealtime --value 2>/dev/null || true)
if [ -z "$TIMER_NEXT" ]; then
    echo "ERROR: $TIMER_UNIT has no next scheduled run, so the daily key will" >&2
    echo "       not rotate and clients will break after the next date change." >&2
    echo "       Check with: systemctl list-timers $TIMER_UNIT" >&2
    exit 1
fi

DATE_BEIJING=$(TZ=Asia/Shanghai date +%Y%m%d)
echo
echo "Service installed and started."
echo "  Key today: ${DATE_BEIJING}<suffix>  (suffix length ${#SUFFIX}, re-derived on each restart)"
echo "  Config:    $ENV_FILE"
echo
echo "Commands:"
echo "  Status:  systemctl status $SERVICE_NAME"
echo "  Logs:    journalctl -u $SERVICE_NAME -f"
echo "  Logfile: $LOG_FILE (rotates to .1 past 10 MiB; empty LOG_FILE in"
echo "           $ENV_FILE = journald only)"
echo "  Sysctl:  $SYSCTL_CONF (kernel UDP buffer ceiling; written only when the"
echo "           host's rmem_max/wmem_max was lower, removed on uninstall)"
echo "  Stop:    systemctl stop $SERVICE_NAME"
echo "  Restart: systemctl restart $SERVICE_NAME"
echo
echo "Note: the key is re-derived from the Beijing date on every (re)start."
echo "A systemd timer restarts the service at 00:00/06:00/12:00/18:00 local"
echo "time, so the server key follows the Beijing date change within seconds."
echo "A client process started before midnight still holds the previous day's"
echo "key, so restart the client as well after the date changes."
echo
systemctl status "$SERVICE_NAME" --no-pager || true
