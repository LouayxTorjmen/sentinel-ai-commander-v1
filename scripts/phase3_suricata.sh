#!/usr/bin/env bash
# =============================================================================
#  scripts/phase3_suricata.sh — Deploy Phase 3: Suricata IDS
#
#  Suricata runs with host networking to capture real traffic.
#  Logs are shared with Wazuh manager via a named Docker volume.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[PHASE 3]${NC} $*"; }
ok()    { echo -e "${GREEN}[PHASE 3]${NC} $*"; }
warn()  { echo -e "${YELLOW}[PHASE 3]${NC} $*"; }
fail()  { echo -e "${RED}[PHASE 3]${NC} $*"; }
fatal() { fail "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo ""
echo "======================================================="
echo "  SENTINEL-AI COMMANDER — Phase 3: Suricata IDS"
echo "======================================================="
echo ""

# ─── Load env ────────────────────────────────────────────────────────────────
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    fatal ".env not found. Run 'make phase1' first."
fi
set -a; source "$PROJECT_ROOT/.env"; set +a

# ─── Check Phase 1 & 2 ──────────────────────────────────────────────────────
info "Checking prerequisites..."
if ! docker inspect --format='{{.State.Health.Status}}' sentinel-wazuh-manager 2>/dev/null | grep -q healthy; then
    fatal "Wazuh Manager not healthy. Run 'make phase1' first."
fi
ok "Phase 1 (Wazuh) running"

if ! docker inspect --format='{{.State.Health.Status}}' sentinel-postgres 2>/dev/null | grep -q healthy; then
    fatal "PostgreSQL not healthy. Run 'make phase2' first."
fi
ok "Phase 2 (Database) running"

# ─── Detect interface ────────────────────────────────────────────────────────
if [ -z "${SURICATA_INTERFACE:-}" ]; then
    SURICATA_INTERFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)
    if [ -n "$SURICATA_INTERFACE" ]; then
        ok "Auto-detected interface: $SURICATA_INTERFACE"
        # Persist to .env
        if ! grep -q "^SURICATA_INTERFACE=" "$PROJECT_ROOT/.env"; then
            echo "SURICATA_INTERFACE=$SURICATA_INTERFACE" >> "$PROJECT_ROOT/.env"
        else
            sed -i "s/^SURICATA_INTERFACE=.*/SURICATA_INTERFACE=$SURICATA_INTERFACE/" "$PROJECT_ROOT/.env"
        fi
    else
        fatal "Could not detect network interface. Set SURICATA_INTERFACE in .env"
    fi
else
    ok "Interface from .env: $SURICATA_INTERFACE"
fi

# ─── Create shared volume for Suricata logs ──────────────────────────────────
info "Setting up Suricata ↔ Wazuh log sharing..."

# Create the named volume if it doesn't exist
if ! docker volume inspect sentinel_suricata_logs &>/dev/null; then
    docker volume create sentinel_suricata_logs >/dev/null
    ok "Created volume: sentinel_suricata_logs"
else
    ok "Volume sentinel_suricata_logs exists"
fi

# ─── Update Wazuh manager to mount Suricata logs ────────────────────────────
# Check if the Wazuh compose already has the suricata volume mount
if ! grep -q "sentinel_suricata_logs" "$PROJECT_ROOT/wazuh/docker-compose.yml"; then
    info "Adding Suricata log volume to Wazuh manager..."

    # Add external volume definition if not present
    if ! grep -q "sentinel_suricata_logs" "$PROJECT_ROOT/wazuh/docker-compose.yml"; then
        # Add volume to the volumes section
        sed -i '/^volumes:/a\  suricata-logs:\n    external: true\n    name: sentinel_suricata_logs' "$PROJECT_ROOT/wazuh/docker-compose.yml"

        # Add volume mount to wazuh-manager service (after the last existing volume mount)
        sed -i '/local_decoder.xml.*:ro/a\      # Suricata shared logs\n      - suricata-logs:/var/log/suricata:ro' "$PROJECT_ROOT/wazuh/docker-compose.yml"

        ok "Wazuh manager now mounts Suricata logs"
    fi
else
    ok "Wazuh manager already mounts Suricata logs"
fi

# ─── Build Suricata image ────────────────────────────────────────────────────
info "Building Suricata image..."
cd "$PROJECT_ROOT"
docker compose build suricata 2>&1 | tail -5
ok "Suricata image built"

# ─── Start Suricata ──────────────────────────────────────────────────────────
info "Starting Suricata..."
docker compose --env-file .env up -d suricata 2>&1

echo ""
info "Waiting for Suricata to initialize (rule updates take ~30s)..."
sleep 30

# ─── Verify ──────────────────────────────────────────────────────────────────
echo ""
info "Verifying Suricata..."

# Check container is running
if docker ps --format '{{.Names}}' | grep -q sentinel-suricata; then
    ok "Suricata container running"
else
    fail "Suricata container not running"
    docker logs sentinel-suricata 2>&1 | tail -10
    exit 1
fi

# Check eve.json is being written
if docker exec sentinel-suricata test -f /var/log/suricata/eve.json 2>/dev/null; then
    EVE_SIZE=$(docker exec sentinel-suricata stat -f%z /var/log/suricata/eve.json 2>/dev/null || docker exec sentinel-suricata stat -c%s /var/log/suricata/eve.json 2>/dev/null || echo "0")
    ok "eve.json exists (${EVE_SIZE} bytes)"
else
    warn "eve.json not yet created (Suricata may still be starting)"
fi

# Check Suricata logs
if docker logs sentinel-suricata 2>&1 | grep -qi "engine started"; then
    ok "Suricata engine started"
else
    warn "Suricata engine may still be starting"
    docker logs sentinel-suricata 2>&1 | tail -5 | sed 's/^/    /'
fi

# ─── Restart Wazuh Manager to pick up Suricata logs ─────────────────────────
info "Restarting Wazuh manager to mount Suricata logs..."
cd "$PROJECT_ROOT/wazuh"
docker compose --env-file "$PROJECT_ROOT/.env" up -d wazuh-manager 2>&1
sleep 15

# Verify manager can see eve.json
if docker exec sentinel-wazuh-manager test -f /var/log/suricata/eve.json 2>/dev/null; then
    ok "Wazuh manager can read Suricata eve.json"
else
    warn "Wazuh manager cannot see eve.json yet — check volume mount"
fi

echo ""
echo "======================================================="
echo "  Phase 3 Complete — Suricata IDS Running"
echo "======================================================="
echo ""
echo "  Interface:    $SURICATA_INTERFACE"
echo "  Logs:         sentinel_suricata_logs volume"
echo "  Custom rules: suricata/rules/custom/local.rules"
echo ""
echo "  Suricata → eve.json → Wazuh manager (localfile)"
echo "  Alerts will appear in Wazuh Dashboard under Security Events"
echo ""
echo "  Ready for Phase 4 (AI Agents + Ansible Runner)."
echo ""
