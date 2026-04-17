#!/usr/bin/env bash
# =============================================================================
#  Suricata Entrypoint — Auto-detect interface, start IDS
#  Supports: WSL2, VM, bare metal, Docker host networking
# =============================================================================
set -e

LOG_DIR="/var/log/suricata"
CONF="/etc/suricata/suricata.yaml"

# ─── Detect network interface ────────────────────────────────────────────────
detect_interface() {
    # 1. Use env var if set
    if [ -n "${SURICATA_INTERFACE:-}" ]; then
        echo "$SURICATA_INTERFACE"
        return
    fi

    # 2. Find default route interface
    local default_if
    default_if=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)
    if [ -n "$default_if" ]; then
        echo "$default_if"
        return
    fi

    # 3. Find first non-loopback interface
    local first_if
    first_if=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -v lo | head -1)
    if [ -n "$first_if" ]; then
        echo "$first_if"
        return
    fi

    echo "eth0"
}

INTERFACE=$(detect_interface)
echo "[SURICATA] Interface: $INTERFACE"
echo "[SURICATA] Config: $CONF"
echo "[SURICATA] Logs: $LOG_DIR"

# ─── Ensure log directory exists and is writable ─────────────────────────────
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# ─── Create eve.json if it doesn't exist (Wazuh needs it) ───────────────────
touch "$LOG_DIR/eve.json"

# ─── Update rules ────────────────────────────────────────────────────────────
echo "[SURICATA] Updating rules..."
suricata-update --no-test 2>&1 | tail -3 || echo "[SURICATA] Rule update failed (continuing with existing rules)"

# ─── Copy custom rules if mounted ────────────────────────────────────────────
if [ -d /custom-rules ] && [ "$(ls -A /custom-rules 2>/dev/null)" ]; then
    echo "[SURICATA] Loading custom rules..."
    cp /custom-rules/*.rules /var/lib/suricata/rules/ 2>/dev/null || true
fi

# ─── Start Suricata ──────────────────────────────────────────────────────────
echo "[SURICATA] Starting Suricata on interface $INTERFACE..."
exec suricata -c "$CONF" -i "$INTERFACE" --set "outputs.0.eve-log.filename=$LOG_DIR/eve.json" -v
