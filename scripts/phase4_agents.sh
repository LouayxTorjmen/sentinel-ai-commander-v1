#!/usr/bin/env bash
# =============================================================================
#  scripts/phase4_agents.sh — Deploy Phase 4: AI Agents + Ansible Runner
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[PHASE 4]${NC} $*"; }
ok()    { echo -e "${GREEN}[PHASE 4]${NC} $*"; }
warn()  { echo -e "${YELLOW}[PHASE 4]${NC} $*"; }
fail()  { echo -e "${RED}[PHASE 4]${NC} $*"; }
fatal() { fail "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo ""
echo "======================================================="
echo "  SENTINEL-AI COMMANDER — Phase 4: AI Agents + Ansible"
echo "======================================================="
echo ""

# ─── Load env ────────────────────────────────────────────────────────────────
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    fatal ".env not found."
fi
set -a; source "$PROJECT_ROOT/.env"; set +a

# ─── Validate critical vars ──────────────────────────────────────────────────
info "Validating configuration..."
for var in GROQ_API_KEY WAZUH_API_PASSWORD POSTGRES_PASSWORD REDIS_PASSWORD WAZUH_INDEXER_PASSWORD; do
    val="${!var:-}"
    if [[ "$val" == "CHANGE_ME"* || -z "$val" ]]; then
        fatal "$var is not set. Edit .env."
    fi
done
ok "Configuration validated"

# ─── Check prerequisites ─────────────────────────────────────────────────────
info "Checking prerequisites..."
for container in sentinel-wazuh-manager sentinel-postgres sentinel-redis; do
    if docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null | grep -q healthy; then
        ok "$container healthy"
    else
        fatal "$container not healthy. Ensure phases 1-3 are running."
    fi
done

# ─── Build images ─────────────────────────────────────────────────────────────
info "Building AI Agents image (this may take 1-2 minutes)..."
cd "$PROJECT_ROOT"
docker compose build ai-agents 2>&1 | tail -5
ok "AI Agents image built"

info "Building Ansible Runner image..."
docker compose build ansible-runner 2>&1 | tail -5
ok "Ansible Runner image built"

# ─── Start services ──────────────────────────────────────────────────────────
info "Starting AI Agents and Ansible Runner..."
docker compose --env-file .env up -d ai-agents ansible-runner 2>&1

echo ""
info "Waiting for services to start..."

# ─── Wait for health ─────────────────────────────────────────────────────────
wait_for_healthy() {
    local container="$1"
    local max_wait="${2:-120}"
    local elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        local status
        status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "not_found")
        case "$status" in
            healthy) ok "$container is healthy"; return 0 ;;
            unhealthy) fail "$container is unhealthy"; docker logs "$container" --tail 10; return 1 ;;
            not_found) fail "$container not found"; return 1 ;;
            *) printf "  %-35s %s (%ds)\r" "$container" "$status" "$elapsed" ;;
        esac
        sleep 5
        elapsed=$((elapsed + 5))
    done
    fail "$container timed out after ${max_wait}s"
    return 1
}

echo ""
wait_for_healthy "sentinel-ansible-runner" 60
wait_for_healthy "sentinel-ai-agents" 120

# ─── Verify ──────────────────────────────────────────────────────────────────
echo ""
info "Verifying services..."

# AI Agents health
if curl -sf http://localhost:${PORT_AI_AGENTS:-50010}/health 2>/dev/null | grep -q ok; then
    ok "AI Agents API responding"
else
    warn "AI Agents API not responding yet"
    docker logs sentinel-ai-agents --tail 10 2>&1 | sed 's/^/    /'
fi

# Ansible Runner health
if curl -sf http://localhost:${PORT_ANSIBLE_RUNNER:-50011}/health 2>/dev/null | grep -q ok; then
    ok "Ansible Runner API responding"
else
    warn "Ansible Runner API not responding yet"
fi

# List available playbooks
PLAYBOOKS=$(curl -sf http://localhost:${PORT_ANSIBLE_RUNNER:-50011}/playbooks 2>/dev/null || echo "{}")
ok "Available playbooks: $PLAYBOOKS"

echo ""
echo "======================================================="
echo "  Phase 4 Complete — AI Agents + Ansible Runner"
echo "======================================================="
echo ""
echo "  AI Agents API:      http://localhost:${PORT_AI_AGENTS:-50010}"
echo "  Ansible Runner API: http://localhost:${PORT_ANSIBLE_RUNNER:-50011}"
echo ""
echo "  Endpoints:"
echo "    GET  /health          — Service health"
echo "    POST /analyze         — Submit alert for AI analysis"
echo "    GET  /incidents       — List incidents"
echo "    POST /correlate       — Wazuh + Suricata correlation"
echo "    GET  /network/summary — Suricata network summary"
echo "    GET  /stats           — Incident statistics"
echo ""
echo "  Ready for Phase 5 (Testing)."
echo ""
