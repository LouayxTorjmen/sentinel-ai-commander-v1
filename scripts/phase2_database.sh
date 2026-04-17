#!/usr/bin/env bash
# =============================================================================
#  scripts/phase2_database.sh — Deploy Phase 2: PostgreSQL, Redis, Nginx
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[PHASE 2]${NC} $*"; }
ok()    { echo -e "${GREEN}[PHASE 2]${NC} $*"; }
warn()  { echo -e "${YELLOW}[PHASE 2]${NC} $*"; }
fail()  { echo -e "${RED}[PHASE 2]${NC} $*"; }
fatal() { fail "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo ""
echo "======================================================="
echo "  SENTINEL-AI COMMANDER — Phase 2: Database + Security"
echo "======================================================="
echo ""

# ─── Load env ────────────────────────────────────────────────────────────────
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    fatal ".env not found. Run 'make phase1' first."
fi
set -a; source "$PROJECT_ROOT/.env"; set +a

# ─── Validate critical vars ──────────────────────────────────────────────────
info "Validating configuration..."
for var in POSTGRES_PASSWORD REDIS_PASSWORD; do
    val="${!var:-}"
    if [[ "$val" == "CHANGE_ME"* || -z "$val" ]]; then
        fatal "$var is not set. Edit .env and set a real password."
    fi
done
ok "Configuration validated"

# ─── Check Phase 1 is running ────────────────────────────────────────────────
info "Checking Phase 1 (Wazuh) is running..."
if docker inspect --format='{{.State.Health.Status}}' sentinel-wazuh-manager 2>/dev/null | grep -q healthy; then
    ok "Wazuh Manager healthy"
else
    fatal "Wazuh Manager not healthy. Run 'make phase1' first."
fi

# Verify bridge networks exist (created by Wazuh stack)
for net in sentinel_wazuh_api_bridge sentinel_wazuh_indexer_bridge; do
    if docker network inspect "$net" &>/dev/null; then
        ok "Network $net exists"
    else
        fatal "Network $net not found. Wazuh stack must be running."
    fi
done

# ─── Check Nginx certs exist ─────────────────────────────────────────────────
if [ ! -f "$PROJECT_ROOT/docker/nginx/certs/sentinel.crt" ]; then
    info "Generating Nginx TLS certificate..."
    bash "$SCRIPT_DIR/gen_certs.sh"
fi
ok "Nginx TLS certificate ready"

# ─── Build Nginx image ───────────────────────────────────────────────────────
info "Building Nginx image..."
cd "$PROJECT_ROOT"
docker compose build nginx 2>&1 | tail -3
ok "Nginx image built"

# ─── Start services ──────────────────────────────────────────────────────────
info "Starting PostgreSQL, Redis, Nginx..."
docker compose --env-file .env up -d postgres redis nginx 2>&1
echo ""

# ─── Wait for health ─────────────────────────────────────────────────────────
info "Waiting for services to become healthy..."

wait_for_healthy() {
    local container="$1"
    local max_wait="${2:-120}"
    local elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        local status
        status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "not_found")
        case "$status" in
            healthy) ok "$container is healthy"; return 0 ;;
            unhealthy) fail "$container is unhealthy"; docker logs "$container" --tail 5; return 1 ;;
            not_found) fail "$container not found"; return 1 ;;
            *) printf "  %-30s %s (%ds)\r" "$container" "$status" "$elapsed" ;;
        esac
        sleep 5
        elapsed=$((elapsed + 5))
    done
    fail "$container timed out after ${max_wait}s"
    return 1
}

echo ""
wait_for_healthy "sentinel-postgres" 60
wait_for_healthy "sentinel-redis" 30
wait_for_healthy "sentinel-nginx" 30

# ─── Verify ──────────────────────────────────────────────────────────────────
echo ""
info "Verifying services..."

# PostgreSQL
if docker exec sentinel-postgres pg_isready -U "${POSTGRES_USER:-sentinel}" &>/dev/null; then
    ok "PostgreSQL accepting connections"
else
    warn "PostgreSQL not ready yet"
fi

# Redis
if docker exec sentinel-redis redis-cli -a "${REDIS_PASSWORD}" ping 2>/dev/null | grep -q PONG; then
    ok "Redis responding (PONG)"
else
    warn "Redis not responding"
fi

# Nginx HTTP → HTTPS redirect
if curl -sf http://localhost:${PORT_NGINX_HTTP:-50020}/nginx-health 2>/dev/null | grep -q ok; then
    ok "Nginx HTTP health endpoint"
else
    warn "Nginx HTTP not responding"
fi

# Nginx HTTPS
if curl -skf https://localhost:${PORT_NGINX_HTTPS:-50021}/nginx-health 2>/dev/null | grep -q ok; then
    ok "Nginx HTTPS health endpoint"
else
    warn "Nginx HTTPS not responding"
fi

# Nginx → Dashboard proxy
if curl -skL https://localhost:${PORT_NGINX_HTTPS:-50021}/ 2>/dev/null | grep -qi wazuh; then
    ok "Nginx → Wazuh Dashboard proxy working"
else
    warn "Nginx → Dashboard proxy not yet ready (dashboard may still be loading)"
fi

echo ""
echo "======================================================="
echo "  Phase 2 Complete — Database + Security Layer Running"
echo "======================================================="
echo ""
echo "  PostgreSQL:   localhost:${PORT_POSTGRES:-50031}"
echo "  Redis:        localhost:${PORT_REDIS:-50030}"
echo "  Nginx HTTP:   http://localhost:${PORT_NGINX_HTTP:-50020}"
echo "  Nginx HTTPS:  https://localhost:${PORT_NGINX_HTTPS:-50021}"
echo ""
echo "  Dashboard via Nginx: https://localhost:${PORT_NGINX_HTTPS:-50021}"
echo ""
echo "  Ready for Phase 3 (Suricata IDS)."
echo ""
