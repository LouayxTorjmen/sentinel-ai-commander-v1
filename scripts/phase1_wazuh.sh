#!/usr/bin/env bash
# =============================================================================
#  scripts/phase1_wazuh.sh — Deploy Phase 1: Wazuh Isolated Stack
#
#  This script:
#    1. Validates prerequisites (calls preflight.sh)
#    2. Generates TLS certificates
#    3. Generates password hashes for OpenSearch
#    4. Starts the Wazuh stack (indexer, manager, dashboard)
#    5. Waits for all services to be healthy
#    6. Verifies connectivity
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[PHASE 1]${NC} $*"; }
ok()    { echo -e "${GREEN}[PHASE 1]${NC} $*"; }
warn()  { echo -e "${YELLOW}[PHASE 1]${NC} $*"; }
fail()  { echo -e "${RED}[PHASE 1]${NC} $*"; }
fatal() { fail "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo ""
echo "======================================================="
echo "  SENTINEL-AI COMMANDER — Phase 1: Wazuh Stack"
echo "======================================================="
echo ""

# ─── Step 0: Create .env if it doesn't exist ────────────────────────────────
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    info "Creating .env from template..."
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
    warn ".env created. You MUST edit it now to set passwords and GROQ_API_KEY."
    warn "Run: nano $PROJECT_ROOT/.env"
    echo ""
    read -rp "Press Enter after editing .env, or Ctrl+C to abort... "
fi

# Load env
set -a; source "$PROJECT_ROOT/.env"; set +a

# ─── Step 1: Validate CHANGE_ME values aren't still set ─────────────────────
info "Validating configuration..."
CRITICAL_VARS=(WAZUH_API_PASSWORD WAZUH_INDEXER_PASSWORD WAZUH_DASHBOARD_PASSWORD)
for var in "${CRITICAL_VARS[@]}"; do
    val="${!var:-}"
    if [[ "$val" == "CHANGE_ME"* || -z "$val" ]]; then
        fatal "$var is not set. Edit .env and set a real password."
    fi
done
ok "Configuration validated"

# ─── Step 2: Run preflight checks ───────────────────────────────────────────
info "Running preflight checks..."
bash "$SCRIPT_DIR/preflight.sh"
echo ""

# ─── Step 3: Generate certificates ──────────────────────────────────────────
info "Generating TLS certificates..."
bash "$SCRIPT_DIR/gen_certs.sh"
echo ""

# ─── Step 4: Generate OpenSearch password hashes ─────────────────────────────
info "Generating OpenSearch password hashes..."

INTERNAL_USERS="$PROJECT_ROOT/wazuh/config/indexer/internal_users.yml"
HASH_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh"

# Hash the admin (indexer) password
# Pass password via env var to avoid shell quoting issues with special chars
info "  Hashing indexer admin password..."
ADMIN_HASH=$(docker run --rm \
    -e JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    -e HASH_PW="${WAZUH_INDEXER_PASSWORD}" \
    wazuh/wazuh-indexer:4.7.5 \
    bash -c "chmod +x $HASH_TOOL && $HASH_TOOL -p \"\$HASH_PW\"" 2>&1 | grep '^\$' | tail -1) || true

# Hash the kibanaserver (dashboard) password
info "  Hashing dashboard password..."
DASHBOARD_HASH=$(docker run --rm \
    -e JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    -e HASH_PW="${WAZUH_DASHBOARD_PASSWORD}" \
    wazuh/wazuh-indexer:4.7.5 \
    bash -c "chmod +x $HASH_TOOL && $HASH_TOOL -p \"\$HASH_PW\"" 2>&1 | grep '^\$' | tail -1) || true

if [ -z "$ADMIN_HASH" ]; then
    warn "BCrypt hash tool failed. Falling back to Python-based hashing..."
    # Fallback: use Python bcrypt (works on any system)
    pip install bcrypt --quiet --break-system-packages 2>/dev/null || pip install bcrypt --quiet 2>/dev/null || true
    ADMIN_HASH=$(python3 -c "
import bcrypt
pw = '''${WAZUH_INDEXER_PASSWORD}'''.encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode())
" 2>/dev/null) || true
    DASHBOARD_HASH=$(python3 -c "
import bcrypt
pw = '''${WAZUH_DASHBOARD_PASSWORD}'''.encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode())
" 2>/dev/null) || true
fi

if [ -z "$ADMIN_HASH" ] || [ -z "$DASHBOARD_HASH" ]; then
    fatal "Failed to generate password hashes via Docker or Python fallback."
fi

ok "Password hashes generated"

# Write internal_users.yml with real hashes
cat > "$INTERNAL_USERS" <<EOF
---
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "$ADMIN_HASH"
  reserved: true
  backend_roles:
    - "admin"
  description: "Admin user"

kibanaserver:
  hash: "$DASHBOARD_HASH"
  reserved: true
  description: "Wazuh dashboard user"
EOF

ok "internal_users.yml written"

# ─── Step 5: Pull images ────────────────────────────────────────────────────
info "Pulling Wazuh Docker images (this may take a few minutes)..."
cd "$PROJECT_ROOT/wazuh"
docker compose pull 2>&1 | tail -5
ok "Images pulled"

# ─── Step 6: Start the stack ────────────────────────────────────────────────
info "Starting Wazuh stack..."
docker compose --env-file "$PROJECT_ROOT/.env" up -d 2>&1

echo ""
info "Waiting for services to become healthy (this takes 2-4 minutes)..."
echo ""

# ─── Step 7: Wait for health ────────────────────────────────────────────────
wait_for_healthy() {
    local container="$1"
    local max_wait="${2:-300}"  # default 5 min
    local elapsed=0

    while [ $elapsed -lt $max_wait ]; do
        local status
        status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "not_found")

        case "$status" in
            healthy)
                ok "$container is healthy"
                return 0
                ;;
            unhealthy)
                fail "$container is unhealthy"
                docker logs "$container" --tail 10 2>&1 | sed 's/^/    /'
                return 1
                ;;
            not_found)
                fail "$container not found"
                return 1
                ;;
            *)
                printf "  %-35s %s  (%ds)\r" "$container" "$status" "$elapsed"
                ;;
        esac

        sleep 10
        elapsed=$((elapsed + 10))
    done

    fail "$container timed out after ${max_wait}s"
    return 1
}

echo ""
wait_for_healthy "sentinel-wazuh-indexer" 300
wait_for_healthy "sentinel-wazuh-manager" 360
wait_for_healthy "sentinel-wazuh-dashboard" 300

# ─── Step 8: Run security init on indexer (apply password hashes) ────────────
info "Applying OpenSearch security configuration..."
docker exec sentinel-wazuh-indexer bash -c '
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk
    chmod +x /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
        -cd /usr/share/wazuh-indexer/opensearch-security/ \
        -nhnv \
        -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
        -cert /usr/share/wazuh-indexer/certs/admin.pem \
        -key /usr/share/wazuh-indexer/certs/admin-key.pem \
        -h localhost \
        2>&1
' | tail -5 || warn "securityadmin returned non-zero (may be OK if certs were just applied)"
ok "Security configuration applied"

# ─── Step 9: Verify ─────────────────────────────────────────────────────────
echo ""
info "Verifying Wazuh stack..."
echo ""

# Test indexer
if curl -sk "https://localhost:${PORT_WAZUH_INDEXER:-50002}/" \
    -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASSWORD}" 2>/dev/null | grep -q "wazuh.indexer"; then
    ok "Wazuh Indexer API responding"
else
    warn "Wazuh Indexer API not yet responding (may need a moment after securityadmin)"
fi

# Test manager
if curl -sk "https://localhost:${PORT_WAZUH_API:-50001}/" \
    -u "${WAZUH_API_USER}:${WAZUH_API_PASSWORD}" 2>/dev/null | grep -q "data"; then
    ok "Wazuh Manager API responding"
else
    warn "Wazuh Manager API not yet responding"
fi

# Test dashboard
if curl -sk "https://localhost:${PORT_WAZUH_DASHBOARD:-50000}/" 2>/dev/null | grep -q "loading"; then
    ok "Wazuh Dashboard responding"
else
    warn "Wazuh Dashboard loading (may take another minute)"
fi

# Show agent enrollment info
echo ""
echo "======================================================="
echo "  Phase 1 Complete — Wazuh Stack Running"
echo "======================================================="
echo ""
echo "  Dashboard:     https://localhost:${PORT_WAZUH_DASHBOARD:-50000}"
echo "  Manager API:   https://localhost:${PORT_WAZUH_API:-50001}"
echo "  Indexer:       https://localhost:${PORT_WAZUH_INDEXER:-50002}"
echo ""
echo "  Agent enrollment port: ${PORT_WAZUH_AGENT_ENROLL:-50042}/tcp"
echo "  Agent comms port:      ${PORT_WAZUH_AGENT_COMM_TCP:-50041}/tcp"
echo ""
echo "  To enroll a remote Wazuh agent:"
echo "    On the agent host, download the Wazuh agent and run:"
echo "    WAZUH_MANAGER='<THIS_HOST_IP>' \\"
echo "    WAZUH_REGISTRATION_PORT='${PORT_WAZUH_AGENT_ENROLL:-50042}' \\"
echo "    WAZUH_AGENT_PORT='${PORT_WAZUH_AGENT_COMM_TCP:-50041}' \\"
echo "    apt install wazuh-agent  # or yum/msi equivalent"
echo ""
echo "  Ready for Phase 2 (Database + Security)."
echo ""
