#!/usr/bin/env bash
# =============================================================================
#  scripts/check_wazuh.sh — Verify all Wazuh services are running and healthy
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a; source "$PROJECT_ROOT/.env"; set +a
fi

PASS=0; FAIL=0

check() {
    local name="$1"; local cmd="$2"
    if eval "$cmd" &>/dev/null; then
        echo -e "  ${GREEN}OK${NC}    $name"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}  $name"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "  Wazuh Stack Health Check"
echo "  ========================"
echo ""

check "Indexer container running"   "docker ps --format '{{.Names}}' | grep -q sentinel-wazuh-indexer"
check "Manager container running"   "docker ps --format '{{.Names}}' | grep -q sentinel-wazuh-manager"
check "Dashboard container running" "docker ps --format '{{.Names}}' | grep -q sentinel-wazuh-dashboard"

check "Indexer healthy"   "[ \"\$(docker inspect --format='{{.State.Health.Status}}' sentinel-wazuh-indexer 2>/dev/null)\" = 'healthy' ]"
check "Manager healthy"   "[ \"\$(docker inspect --format='{{.State.Health.Status}}' sentinel-wazuh-manager 2>/dev/null)\" = 'healthy' ]"

check "Indexer API"       "curl -sk https://localhost:${PORT_WAZUH_INDEXER:-50002}/ -u ${WAZUH_INDEXER_USER:-admin}:${WAZUH_INDEXER_PASSWORD:-pass} | grep -q wazuh"
check "Manager API"       "curl -sk https://localhost:${PORT_WAZUH_API:-50001}/ | grep -q title"
check "Dashboard loading" "curl -skL --max-time 15 -o /tmp/dash.html https://localhost:${PORT_WAZUH_DASHBOARD:-50000}/ 2>/dev/null && grep -qi wazuh /tmp/dash.html"

# Check agent enrollment port is open
check "Agent enrollment port (${PORT_WAZUH_AGENT_ENROLL:-50042})" \
    "bash -c '</dev/tcp/localhost/${PORT_WAZUH_AGENT_ENROLL:-50042}' 2>/dev/null"

echo ""
echo "  Results: $PASS passed, $FAIL failed"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}All Wazuh services healthy.${NC}"
    exit 0
else
    echo -e "  ${YELLOW}Some checks failed. Services may still be starting (wait 1-2 min and retry).${NC}"
    exit 1
fi
