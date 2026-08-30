#!/usr/bin/env bash
# Uninstall kcp-proxy-server systemd service (self-contained).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------- config: common.sh if available, else built-in defaults ----------
if [ -f "$SCRIPT_DIR/../runtime/common.sh" ]; then
    source "$SCRIPT_DIR/../runtime/common.sh"
elif [ -f "$SCRIPT_DIR/../../scripts/common.sh" ]; then
    source "$SCRIPT_DIR/../../scripts/common.sh"
else
    INSTALL_DIR="/usr/local/bin/kcp-proxy"
    ENV_DIR="/etc/kcp-proxy"
    SERVICE_NAME="kcp-proxy-server.service"
    SERVICE_USER="kcpproxy"
fi

PURGE=0
if [ "${1:-}" = "--purge" ]; then
    PURGE=1
elif [ -n "${1:-}" ]; then
    echo "Usage: $0 [--purge]" >&2
    exit 1
fi
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root" >&2
    exit 1
fi


echo "Stopping and disabling $SERVICE_NAME ..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true

# Also clean up any legacy @template instances
for unit in $(systemctl list-units --type=service --all 'kcp-proxy-server@*.service' --no-legend 2>/dev/null | awk '{print $1}'); do
    echo "Stopping legacy $unit ..."
    systemctl stop "$unit" || true
    systemctl disable "$unit" || true
done

# Remove unit files
rm -f "/etc/systemd/system/$SERVICE_NAME"
rm -f /etc/systemd/system/kcp-proxy-server@.service

# Remove timer units
TIMER_SERVICE="kcp-proxy-server-key-refresh.service"
TIMER_UNIT="kcp-proxy-server-key-refresh.timer"
systemctl disable --now "$TIMER_UNIT" 2>/dev/null || true
rm -f "/etc/systemd/system/$TIMER_SERVICE" "/etc/systemd/system/$TIMER_UNIT"

# Remove any legacy cron entry only when explicitly purging legacy installs.
if [ "$PURGE" -eq 1 ] && command -v crontab >/dev/null 2>&1; then
    remaining=$(crontab -l 2>/dev/null | grep -vF '# kcp-proxy-server' || true)
    if [ -n "$remaining" ]; then
        printf '%s\n' "$remaining" | crontab -
    else
        crontab -r 2>/dev/null || true
    fi
fi

# Remove binaries; keep configuration for ordinary remove.
rm -rf "$INSTALL_DIR"
if [ "$PURGE" -eq 1 ]; then
    [ "$ENV_DIR" = "/etc/kcp-proxy" ] || { echo "Refusing unexpected ENV_DIR: $ENV_DIR" >&2; exit 1; }
    rm -rf "$ENV_DIR"
fi

# Remove service user
if id "$SERVICE_USER" &>/dev/null; then
    userdel "$SERVICE_USER" 2>/dev/null || true
fi

systemctl daemon-reload

echo
echo "kcp-proxy-server uninstalled (configuration $([ "$PURGE" -eq 1 ] && echo removed || echo preserved))."
