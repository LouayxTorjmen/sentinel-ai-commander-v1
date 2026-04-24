#!/usr/bin/env bash
# =============================================================================
#  scripts/install_inventory_sync.sh — Install Wazuh IT Hygiene sync pipeline
#
#  Works around a confirmed Wazuh 4.14 limitation where bulk inventory data
#  (packages, users, groups, networks, protocols) is stranded in the manager's
#  wazuh-db and never pushed to the OpenSearch indices that back IT Hygiene.
#
#  This script:
#    1. Injects indexer credentials into the wazuh-manager keystore (every
#       time the container is recreated the keystore is lost — this step is
#       safe to re-run).
#    2. Copies scripts/sync_inventory.py into the container.
#    3. Runs the sync script once to seed the indices.
#    4. Registers a host cron entry running the sync every minute.
#
#  Requirements:
#    - sentinel-wazuh-manager container must be running and healthy
#    - .env must contain WAZUH_INDEXER_PASSWORD and WAZUH_INDEXER_USER
#    - Host must have crontab (install cronie/cron if missing)
#
#  Re-run is idempotent; safe after every `docker compose up --force-recreate`.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[inventory-sync]${NC} $*"; }
ok()    { echo -e "${GREEN}[inventory-sync]${NC} $*"; }
warn()  { echo -e "${YELLOW}[inventory-sync]${NC} $*"; }
fail()  { echo -e "${RED}[inventory-sync]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ─── Load environment ────────────────────────────────────────────────────────
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    fail ".env not found at $PROJECT_ROOT/.env — run phase1 first"
    exit 1
fi
set -a
# shellcheck disable=SC1091
source "$PROJECT_ROOT/.env"
set +a

INDEXER_USER="${WAZUH_INDEXER_USER:-admin}"
INDEXER_PASS="${WAZUH_INDEXER_PASSWORD:-}"

if [ -z "$INDEXER_PASS" ]; then
    fail "WAZUH_INDEXER_PASSWORD is not set in .env"
    exit 1
fi

MANAGER_CONTAINER="sentinel-wazuh-manager"
SYNC_SRC="$PROJECT_ROOT/scripts/sync_inventory.py"
SYNC_DEST="/usr/local/bin/sync_inventory.py"

# ─── 0. Preflight: is the manager container running? ────────────────────────
if ! command -v flock >/dev/null 2>&1; then
    fail "flock(1) not found — install util-linux (apt install util-linux / dnf install util-linux-core)"
    exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q "^${MANAGER_CONTAINER}\$"; then
    fail "Container ${MANAGER_CONTAINER} is not running."
    warn "Start the Wazuh stack first:  make wazuh-up  (or  make phase1)"
    exit 1
fi

# ─── 1. Inject indexer credentials into the keystore ────────────────────────
# This is required because the keystore lives inside the container (not a
# volume) and is lost on every `docker compose up --force-recreate`.
info "Injecting indexer credentials into wazuh-keystore..."
docker exec "$MANAGER_CONTAINER" bash -c \
    "echo -n '$INDEXER_USER' | /var/ossec/bin/wazuh-keystore -f indexer -k username" \
    > /dev/null
docker exec "$MANAGER_CONTAINER" bash -c \
    "echo -n '$INDEXER_PASS' | /var/ossec/bin/wazuh-keystore -f indexer -k password" \
    > /dev/null
ok "Keystore updated"

# ─── 2. Copy sync_inventory.py into the container ───────────────────────────
if [ ! -f "$SYNC_SRC" ]; then
    fail "sync_inventory.py not found at $SYNC_SRC"
    exit 1
fi

info "Installing sync_inventory.py into $MANAGER_CONTAINER:$SYNC_DEST ..."
docker cp "$SYNC_SRC" "$MANAGER_CONTAINER:$SYNC_DEST"
docker exec "$MANAGER_CONTAINER" chmod +x "$SYNC_DEST"

# Inject the indexer credentials as an env var the script can read.  The
# script already defaults to admin:Louay@2002 but should not have hard-coded
# passwords outside the env file in production.  We set it via Docker exec's
# --env so the password never lives in the filesystem inside the container.
ok "Script installed"

# ─── 3. Run the sync once to seed indices ───────────────────────────────────
info "Running initial sync (this may take 30–60s)..."
if docker exec \
    -e "WAZUH_INVENTORY_SYNC_CREDS=${INDEXER_USER}:${INDEXER_PASS}" \
    "$MANAGER_CONTAINER" python3 "$SYNC_DEST"; then
    ok "Initial sync completed"
else
    warn "Initial sync returned non-zero. Check output above."
    warn "Common causes: wazuh-db socket down (try: docker exec $MANAGER_CONTAINER /var/ossec/bin/wazuh-control start)"
fi

# ─── 4. Install host cron job (every minute) ────────────────────────────
CRON_MARKER="# wazuh-inventory-sync (sentinel-ai-commander)"
# Run every minute. flock prevents overlapping runs if the sync ever takes
# longer than 60s (an agent's SQLite is unreachable, large packages table, etc).
# -n = fail fast if already locked (don't queue); -x = exclusive lock.
CRON_CMD="* * * * * /usr/bin/flock -n /tmp/wazuh_inventory_sync.lock -c \"docker exec -e WAZUH_INVENTORY_SYNC_CREDS='${INDEXER_USER}:${INDEXER_PASS}' $MANAGER_CONTAINER python3 $SYNC_DEST\" >> /var/log/wazuh_inventory_auto.log 2>&1"

info "Installing host cron job (every minute)..."

# Read existing crontab (may be empty).  Strip any previous sentinel entry
# so re-runs don't stack duplicates.
CURRENT_CRON="$(crontab -l 2>/dev/null || true)"
CLEANED="$(echo "$CURRENT_CRON" | grep -v -F "$CRON_MARKER" | grep -v -F "sync_inventory.py" || true)"

# Rebuild with our marker + command appended
{
    printf '%s\n' "$CLEANED"
    printf '%s\n' "$CRON_MARKER"
    printf '%s\n' "$CRON_CMD"
} | crontab -

ok "Cron entry installed. Verify with:  crontab -l | grep sync_inventory"

# ─── 5. Ensure log file exists and is readable ──────────────────────────────
sudo touch /var/log/wazuh_inventory_auto.log 2>/dev/null || touch /var/log/wazuh_inventory_auto.log 2>/dev/null || true

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
ok "IT Hygiene inventory sync pipeline installed."
echo ""
echo "  Monitor the sync log:"
echo "    tail -f /var/log/wazuh_inventory_auto.log"
echo ""
echo "  Manually trigger a sync at any time:"
echo "    docker exec $MANAGER_CONTAINER python3 $SYNC_DEST"
echo ""
echo "  When a new agent is enrolled via enroll.py, it will be picked up"
echo "  automatically on the next 1-minute tick (no extra action required)."
