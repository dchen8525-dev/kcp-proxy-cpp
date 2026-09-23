#!/usr/bin/env bash
# Uninstall kcp-proxy-server systemd service (self-contained).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------- config: common.sh if available, else built-in defaults ----------
# Deploy package: common.sh is shipped next to this script. Repo checkout: it
# lives in ../runtime/. The old ../../scripts/common.sh fallback never existed.
if [ -f "$SCRIPT_DIR/common.sh" ]; then
    source "$SCRIPT_DIR/common.sh"
elif [ -f "$SCRIPT_DIR/../runtime/common.sh" ]; then
    source "$SCRIPT_DIR/../runtime/common.sh"
else
    INSTALL_DIR="/usr/local/bin/kcp-proxy"
    ENV_DIR="/etc/kcp-proxy"
    SERVICE_NAME="kcp-proxy-server.service"
    SERVICE_USER="kcpproxy"
    SYSCTL_CONF="/etc/sysctl.d/99-kcp-proxy.conf"
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
    LOG_DIR="$(dirname "${LOG_FILE:-/var/log/kcp-proxy/server.log}")"
    if [ "$LOG_DIR" = "/var/log/kcp-proxy" ]; then
        rm -rf "$LOG_DIR"
    else
        echo "Keeping custom log directory: $LOG_DIR"
    fi
fi

# Remove service user
if id "$SERVICE_USER" &>/dev/null; then
    userdel "$SERVICE_USER" 2>/dev/null || true
fi

# Remove the kernel UDP buffer ceiling drop-in. Unconditional (not gated on
# --purge): it exists only to serve the service, and leaving a sysctl drop-in
# behind after an uninstall would silently cap rmem_max for the whole host.
#
# The drop-in is not rolled back to the host's pre-install value -- the
# installer never recorded it, and inventing one now risks writing a *lower*
# ceiling than the host wants. So the notice below is deliberate: the live
# rmem_max stays raised until the next reboot, and the operator is told.
SYSCTL_REMOVED=0
if [ -f "$SYSCTL_CONF" ]; then
    rm -f "$SYSCTL_CONF"
    SYSCTL_REMOVED=1
    # Deliberately no `sysctl` call here: deleting a drop-in does not lower a
    # value that is already live (sysctl only ever *sets* what the files say),
    # so running it would be theatre. The notice below is the honest report.
fi

systemctl daemon-reload

echo
echo "kcp-proxy-server uninstalled (configuration $([ "$PURGE" -eq 1 ] && echo removed || echo preserved))."
if [ "$SYSCTL_REMOVED" -eq 1 ]; then
    echo
    echo "Note: removed $SYSCTL_CONF. The kernel keeps the raised UDP buffer"
    echo "      ceiling until the next reboot (the pre-install value was not"
    echo "      recorded, so it is not restored automatically)."
fi
