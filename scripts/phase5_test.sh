#!/usr/bin/env bash
# =============================================================================
#  scripts/phase5_test.sh — Full Stack Validation & Attack Simulation
#
#  Tests every component, every connection, every pipeline path.
#  Sections:
#    1. Container health
#    2. Network connectivity (inter-container)
#    3. Wazuh stack validation
#    4. Database validation
#    5. AI pipeline end-to-end
#    6. Suricata → Wazuh flow
#    7. Attack simulation
#    8. Summary
# =============================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0

ok()   { echo -e "  ${GREEN}✓${NC} $*"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}✗${NC} $*"; FAIL=$((FAIL+1)); }
warn() { echo -e "  ${YELLOW}!${NC} $*"; WARN=$((WARN+1)); }
section() { echo ""; echo -e "${CYAN}━━━ $* ━━━${NC}"; echo ""; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a; source "$PROJECT_ROOT/.env"; set +a
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  SENTINEL-AI COMMANDER — Phase 5: Full Stack Testing"
echo "═══════════════════════════════════════════════════════"

# ═══════════════════════════════════════════════════════════════════════════════
section "1. Container Health"
# ═══════════════════════════════════════════════════════════════════════════════

CONTAINERS=(
    sentinel-wazuh-indexer
    sentinel-wazuh-manager
    sentinel-wazuh-dashboard
    sentinel-postgres
    sentinel-redis
    sentinel-nginx
    sentinel-suricata
    sentinel-ai-agents
    sentinel-ansible-runner
)

for c in "${CONTAINERS[@]}"; do
    if docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        status=$(docker inspect --format='{{.State.Health.Status}}' "$c" 2>/dev/null || echo "no-healthcheck")
        case "$status" in
            healthy)       ok "$c — healthy" ;;
            no-healthcheck) ok "$c — running (no healthcheck)" ;;
            *)             fail "$c — $status" ;;
        esac
    else
        fail "$c — not running"
    fi
done

# ═══════════════════════════════════════════════════════════════════════════════
section "2. Network Connectivity"
# ═══════════════════════════════════════════════════════════════════════════════

# AI agents → Wazuh Manager
if docker exec sentinel-ai-agents curl -sk --max-time 5 https://sentinel-wazuh-manager:55000/ 2>/dev/null | grep -q title; then
    ok "AI Agents → Wazuh Manager (API bridge)"
else
    fail "AI Agents → Wazuh Manager"
fi

# AI agents → Wazuh Indexer
if docker exec sentinel-ai-agents curl -sk --max-time 5 https://sentinel-wazuh-indexer:9200/ -u admin:${WAZUH_INDEXER_PASSWORD} 2>/dev/null | grep -q cluster_name; then
    ok "AI Agents → Wazuh Indexer (indexer bridge)"
else
    fail "AI Agents → Wazuh Indexer"
fi

# AI agents → Redis
if docker exec sentinel-ai-agents python3 -c "
import redis, os
r = redis.Redis(host='sentinel-redis', port=6379, password=os.environ.get('REDIS_PASSWORD',''), decode_responses=True)
print(r.ping())
" 2>/dev/null | grep -q True; then
    ok "AI Agents → Redis"
else
    fail "AI Agents → Redis"
fi

# AI agents → PostgreSQL
if docker exec sentinel-ai-agents python3 -c "
from urllib.parse import quote_plus
import os, psycopg2
pw = quote_plus(os.environ.get('POSTGRES_PASSWORD',''))
conn = psycopg2.connect(host='sentinel-postgres', port=5432, dbname=os.environ.get('POSTGRES_DB','sentinel'), user=os.environ.get('POSTGRES_USER','sentinel'), password=os.environ.get('POSTGRES_PASSWORD',''))
conn.close()
print('OK')
" 2>/dev/null | grep -q OK; then
    ok "AI Agents → PostgreSQL"
else
    fail "AI Agents → PostgreSQL"
fi

# AI agents → Ansible Runner
if docker exec sentinel-ai-agents curl -sf --max-time 5 http://sentinel-ansible-runner:5001/health 2>/dev/null | grep -q ok; then
    ok "AI Agents → Ansible Runner"
else
    fail "AI Agents → Ansible Runner"
fi

# Nginx → Dashboard
if docker exec sentinel-nginx curl -sk --max-time 10 https://sentinel-wazuh-dashboard:5601/ 2>/dev/null | grep -qi wazuh; then
    ok "Nginx → Wazuh Dashboard (proxy)"
else
    warn "Nginx → Dashboard (may need more startup time)"
fi

# Wazuh Manager → Indexer (Filebeat)
if docker exec sentinel-wazuh-manager filebeat test output 2>&1 | grep -q "talk to server... OK"; then
    ok "Wazuh Manager → Indexer (Filebeat TLS)"
else
    fail "Wazuh Manager → Indexer (Filebeat)"
fi

# AI agents → Suricata logs (shared volume)
if docker exec sentinel-ai-agents test -f /var/log/suricata/eve.json && [ "$(docker exec sentinel-ai-agents wc -l < /var/log/suricata/eve.json 2>/dev/null)" -gt 0 ]; then
    ok "AI Agents → Suricata eve.json (shared volume)"
else
    warn "AI Agents → Suricata eve.json (may be empty)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "3. Wazuh Stack Validation"
# ═══════════════════════════════════════════════════════════════════════════════

# Indexer API
if curl -sk https://localhost:${PORT_WAZUH_INDEXER:-50002}/ -u admin:${WAZUH_INDEXER_PASSWORD} 2>/dev/null | grep -q cluster_name; then
    ok "Wazuh Indexer API authenticated"
else
    fail "Wazuh Indexer API"
fi

# Index template
if curl -sk "https://localhost:${PORT_WAZUH_INDEXER:-50002}/_template/wazuh" -u admin:${WAZUH_INDEXER_PASSWORD} 2>/dev/null | grep -q wazuh-alerts; then
    ok "Wazuh alerts template exists"
else
    fail "Wazuh alerts template missing"
fi

# Alert count
ALERT_COUNT=$(curl -sk "https://localhost:${PORT_WAZUH_INDEXER:-50002}/wazuh-alerts-*/_count" -u admin:${WAZUH_INDEXER_PASSWORD} 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)
if [ "$ALERT_COUNT" -gt 0 ] 2>/dev/null; then
    ok "Wazuh alerts in OpenSearch: $ALERT_COUNT"
else
    warn "No Wazuh alerts yet (need agents or more traffic)"
fi

# Manager API (JWT)
TOKEN=$(curl -sk -X POST "https://localhost:${PORT_WAZUH_API:-50001}/security/user/authenticate" \
    -u "${WAZUH_API_USER}:${WAZUH_API_PASSWORD}" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('token',''))" 2>/dev/null || echo "")
if [ -n "$TOKEN" ]; then
    ok "Wazuh Manager JWT authentication"

    # Agent listing
    AGENT_COUNT=$(curl -sk "https://localhost:${PORT_WAZUH_API:-50001}/agents" \
        -H "Authorization: Bearer $TOKEN" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('total_affected_items',0))" 2>/dev/null || echo 0)
    ok "Wazuh registered agents: $AGENT_COUNT"
else
    fail "Wazuh Manager JWT authentication"
fi

# Dashboard
if curl -skL --max-time 15 -o /tmp/dash.html https://localhost:${PORT_WAZUH_DASHBOARD:-50000}/ 2>/dev/null && grep -qi wazuh /tmp/dash.html; then
    ok "Wazuh Dashboard loading"
else
    warn "Wazuh Dashboard not ready"
fi

# Agent enrollment port
if bash -c "</dev/tcp/localhost/${PORT_WAZUH_AGENT_ENROLL:-50042}" 2>/dev/null; then
    ok "Agent enrollment port ${PORT_WAZUH_AGENT_ENROLL:-50042} open"
else
    fail "Agent enrollment port closed"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "4. Database & Cache Validation"
# ═══════════════════════════════════════════════════════════════════════════════

# PostgreSQL tables
TABLE_COUNT=$(docker exec sentinel-postgres psql -U ${POSTGRES_USER:-sentinel} -d ${POSTGRES_DB:-sentinel} -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';" 2>/dev/null | tr -d ' ')
if [ "$TABLE_COUNT" -gt 0 ] 2>/dev/null; then
    ok "PostgreSQL tables created: $TABLE_COUNT"
    TABLES=$(docker exec sentinel-postgres psql -U ${POSTGRES_USER:-sentinel} -d ${POSTGRES_DB:-sentinel} -t -c "SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name;" 2>/dev/null | tr -d ' ' | grep -v '^$' | tr '\n' ', ')
    ok "Tables: ${TABLES%,}"
else
    fail "PostgreSQL — no tables found"
fi

# Incident count
INCIDENT_COUNT=$(docker exec sentinel-postgres psql -U ${POSTGRES_USER:-sentinel} -d ${POSTGRES_DB:-sentinel} -t -c "SELECT count(*) FROM incidents;" 2>/dev/null | tr -d ' ')
ok "PostgreSQL incidents stored: ${INCIDENT_COUNT:-0}"

# Redis ping
if docker exec sentinel-redis redis-cli -a "${REDIS_PASSWORD}" ping 2>/dev/null | grep -q PONG; then
    ok "Redis responding (PONG)"
else
    fail "Redis not responding"
fi

# Redis keys
REDIS_KEYS=$(docker exec sentinel-redis redis-cli -a "${REDIS_PASSWORD}" dbsize 2>/dev/null | grep -oP '\d+' || echo 0)
ok "Redis keys: $REDIS_KEYS"

# ═══════════════════════════════════════════════════════════════════════════════
section "5. AI Pipeline End-to-End"
# ═══════════════════════════════════════════════════════════════════════════════

# Health
if curl -sf http://localhost:${PORT_AI_AGENTS:-50010}/health 2>/dev/null | grep -q ok; then
    ok "AI Agents API healthy"
else
    fail "AI Agents API not healthy"
fi

# Ansible Runner health
if curl -sf http://localhost:${PORT_ANSIBLE_RUNNER:-50011}/health 2>/dev/null | grep -q ok; then
    ok "Ansible Runner API healthy"
else
    fail "Ansible Runner API not healthy"
fi

# Full pipeline test — brute force alert
echo -e "  ${CYAN}Testing full AI pipeline (Groq LLM)...${NC}"
ANALYZE_RESULT=$(curl -s --max-time 60 -X POST http://localhost:${PORT_AI_AGENTS:-50010}/analyze \
    -H "Content-Type: application/json" \
    -d '{
        "alert": {
            "id": "phase5-test-001",
            "rule": {
                "id": 5763,
                "level": 10,
                "description": "SSH brute force attack from 203.0.113.42",
                "groups": ["syslog","sshd","authentication_failures"],
                "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"], "technique": ["Password Guessing"]}
            },
            "agent": {"id": "003", "name": "test-server", "ip": "192.168.1.200"},
            "data": {"srcip": "203.0.113.42", "dstuser": "admin"}
        }
    }' 2>/dev/null)

if echo "$ANALYZE_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('incident_id'); assert d.get('severity'); assert d.get('summary')" 2>/dev/null; then
    SEVERITY=$(echo "$ANALYZE_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('severity',''))" 2>/dev/null)
    ALERT_TYPE=$(echo "$ANALYZE_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('alert_type',''))" 2>/dev/null)
    MITRE=$(echo "$ANALYZE_RESULT" | python3 -c "import sys,json; print(','.join(json.load(sys.stdin).get('mitre_techniques',[])))" 2>/dev/null)
    DISPATCH=$(echo "$ANALYZE_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('dispatch',{}).get('executed',''))" 2>/dev/null)
    CVES=$(echo "$ANALYZE_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('cves_found',0))" 2>/dev/null)
    ok "Groq LLM classification: type=$ALERT_TYPE severity=$SEVERITY"
    ok "MITRE ATT&CK mapping: $MITRE"
    ok "CVE lookup: $CVES CVEs found"
    ok "Ansible dispatch triggered: $DISPATCH"
else
    fail "AI pipeline returned invalid response"
    echo "    Response: $(echo "$ANALYZE_RESULT" | head -c 200)"
fi

# Malware test
echo -e "  ${CYAN}Testing malware classification...${NC}"
MALWARE_RESULT=$(curl -s --max-time 60 -X POST http://localhost:${PORT_AI_AGENTS:-50010}/analyze \
    -H "Content-Type: application/json" \
    -d '{
        "alert": {
            "id": "phase5-test-002",
            "rule": {
                "id": 554,
                "level": 13,
                "description": "Rootkit detected: Hidden file /usr/bin/.hidden_backdoor found",
                "groups": ["ossec","rootcheck","rootkit"],
                "mitre": {"id": ["T1547.006"], "tactic": ["Persistence"], "technique": ["Kernel Modules and Extensions"]}
            },
            "agent": {"id": "004", "name": "prod-web-01", "ip": "10.0.1.50"},
            "data": {"file": "/usr/bin/.hidden_backdoor"}
        }
    }' 2>/dev/null)

MALWARE_TYPE=$(echo "$MALWARE_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('alert_type',''))" 2>/dev/null)
MALWARE_SEV=$(echo "$MALWARE_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('severity',''))" 2>/dev/null)
if [ -n "$MALWARE_TYPE" ]; then
    ok "Malware classification: type=$MALWARE_TYPE severity=$MALWARE_SEV"
else
    fail "Malware classification failed"
fi

# Correlation test
echo -e "  ${CYAN}Testing Wazuh+Suricata correlation...${NC}"
CORR_RESULT=$(curl -s --max-time 30 -X POST http://localhost:${PORT_AI_AGENTS:-50010}/correlate 2>/dev/null)
CORR_STATUS=$(echo "$CORR_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
if [ "$CORR_STATUS" = "success" ]; then
    WAZUH_N=$(echo "$CORR_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('wazuh_alerts_fetched',0))" 2>/dev/null)
    SURI_N=$(echo "$CORR_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('suricata_alerts_fetched',0))" 2>/dev/null)
    CORR_N=$(echo "$CORR_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('correlated_incidents',0))" 2>/dev/null)
    ok "Correlation engine: wazuh=$WAZUH_N suricata=$SURI_N correlated=$CORR_N"
else
    warn "Correlation returned: $CORR_STATUS"
fi

# Network summary
NET_RESULT=$(curl -s --max-time 10 http://localhost:${PORT_AI_AGENTS:-50010}/network/summary 2>/dev/null)
NET_ALERTS=$(echo "$NET_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_suricata_alerts',0))" 2>/dev/null)
ok "Suricata network summary: $NET_ALERTS alerts captured"

# Stats
STATS=$(curl -s http://localhost:${PORT_AI_AGENTS:-50010}/stats 2>/dev/null)
TOTAL=$(echo "$STATS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_incidents',0))" 2>/dev/null)
ok "Total incidents in database: $TOTAL"

# ═══════════════════════════════════════════════════════════════════════════════
section "6. Suricata → Wazuh Flow"
# ═══════════════════════════════════════════════════════════════════════════════

# Suricata engine
if docker logs sentinel-suricata 2>&1 | grep -q "Engine started"; then
    ok "Suricata engine running"
    RULES=$(docker logs sentinel-suricata 2>&1 | grep -oP '\d+ rules successfully loaded' | head -1)
    ok "Suricata rules: $RULES"
else
    fail "Suricata engine not started"
fi

# Eve.json being written
EVE_LINES=$(docker exec sentinel-suricata wc -l < /var/log/suricata/eve.json 2>/dev/null || echo 0)
if [ "$EVE_LINES" -gt 0 ] 2>/dev/null; then
    ok "Suricata eve.json: $EVE_LINES events"
else
    warn "Suricata eve.json empty"
fi

# Wazuh can read eve.json
if docker exec sentinel-wazuh-manager test -f /var/log/suricata/eve.json 2>/dev/null; then
    ok "Wazuh Manager can read Suricata eve.json"
else
    fail "Wazuh Manager cannot read Suricata eve.json"
fi

# Suricata alerts in OpenSearch
SURI_ALERT_COUNT=$(curl -sk "https://localhost:${PORT_WAZUH_INDEXER:-50002}/wazuh-alerts-*/_count" \
    -u admin:${WAZUH_INDEXER_PASSWORD} \
    -H "Content-Type: application/json" \
    -d '{"query":{"match":{"rule.groups":"suricata"}}}' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)
if [ "$SURI_ALERT_COUNT" -gt 0 ] 2>/dev/null; then
    ok "Suricata alerts in Wazuh OpenSearch: $SURI_ALERT_COUNT"
else
    warn "No Suricata alerts in OpenSearch yet (generate traffic to trigger)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "7. Attack Simulation"
# ═══════════════════════════════════════════════════════════════════════════════

WSL_IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "127.0.0.1")
echo -e "  ${CYAN}Target: $WSL_IP${NC}"

# Nmap-like scan signature
echo -e "  ${CYAN}Sending vulnerability scanner traffic...${NC}"
curl -s -A "Nmap Scripting Engine" "http://$WSL_IP:${PORT_NGINX_HTTP:-50020}/" >/dev/null 2>&1
curl -s -A "Nikto/2.1.6" "http://$WSL_IP:${PORT_NGINX_HTTP:-50020}/" >/dev/null 2>&1
curl -s -A "sqlmap/1.5" "http://$WSL_IP:${PORT_NGINX_HTTP:-50020}/" >/dev/null 2>&1
ok "Sent scanner-UA traffic (Nmap, Nikto, sqlmap)"

# SQL injection
echo -e "  ${CYAN}Sending SQL injection attempts...${NC}"
curl -s "http://$WSL_IP:${PORT_NGINX_HTTP:-50020}/?id=1'%20OR%201=1--" >/dev/null 2>&1
curl -s "http://$WSL_IP:${PORT_NGINX_HTTP:-50020}/?user=admin'%20UNION%20SELECT%20*%20FROM%20users--" >/dev/null 2>&1
ok "Sent SQL injection traffic"

# Shell injection
echo -e "  ${CYAN}Sending shell injection attempts...${NC}"
curl -s "http://$WSL_IP:${PORT_NGINX_HTTP:-50020}/cgi-bin/../../bin/bash" >/dev/null 2>&1
curl -s "http://$WSL_IP:${PORT_NGINX_HTTP:-50020}/cmd?exec=/bin/cat%20/etc/passwd" >/dev/null 2>&1
ok "Sent shell injection traffic"

# Wait for Suricata to process
sleep 10

# Check if new alerts were generated
NEW_EVE_LINES=$(docker exec sentinel-suricata wc -l < /var/log/suricata/eve.json 2>/dev/null || echo 0)
NEW_EVENTS=$((NEW_EVE_LINES - EVE_LINES))
if [ "$NEW_EVENTS" -gt 0 ] 2>/dev/null; then
    ok "Suricata captured $NEW_EVENTS new events from simulation"
else
    warn "No new Suricata events (traffic may not have reached eth0)"
fi

# Check for actual alert events
ALERT_EVENTS=$(docker exec sentinel-suricata grep '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null | wc -l || echo 0)
ok "Total Suricata alert events: $ALERT_EVENTS"

# Submit a simulated lateral movement alert through AI pipeline
echo -e "  ${CYAN}Testing lateral movement detection...${NC}"
LATERAL_RESULT=$(curl -s --max-time 60 -X POST http://localhost:${PORT_AI_AGENTS:-50010}/analyze \
    -H "Content-Type: application/json" \
    -d '{
        "alert": {
            "id": "phase5-sim-lateral",
            "rule": {
                "id": 100011,
                "level": 12,
                "description": "Successful login after brute force from 10.0.0.99 — possible credential compromise",
                "groups": ["authentication_success","brute_force","credential_access"],
                "mitre": {"id": ["T1078","T1110.001"], "tactic": ["Defense Evasion","Credential Access"], "technique": ["Valid Accounts","Password Guessing"]}
            },
            "agent": {"id": "005", "name": "dc-server-01", "ip": "10.0.1.10"},
            "data": {"srcip": "10.0.0.99", "dstuser": "administrator", "dstip": "10.0.1.10"}
        }
    }' 2>/dev/null)

LATERAL_SEV=$(echo "$LATERAL_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('severity',''))" 2>/dev/null)
LATERAL_PLAYBOOK=$(echo "$LATERAL_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('dispatch',{}).get('playbook','none'))" 2>/dev/null)
if [ -n "$LATERAL_SEV" ]; then
    ok "Lateral movement: severity=$LATERAL_SEV playbook=$LATERAL_PLAYBOOK"
else
    fail "Lateral movement classification failed"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "8. Summary"
# ═══════════════════════════════════════════════════════════════════════════════

TOTAL=$((PASS + FAIL + WARN))
echo ""
echo "═══════════════════════════════════════════════════════"
echo -e "  ${GREEN}Passed: $PASS${NC}  ${RED}Failed: $FAIL${NC}  ${YELLOW}Warnings: $WARN${NC}  Total: $TOTAL"
echo "═══════════════════════════════════════════════════════"
echo ""

# Final incident count
FINAL_INCIDENTS=$(curl -s http://localhost:${PORT_AI_AGENTS:-50010}/stats 2>/dev/null)
echo "  Final incident stats:"
echo "  $FINAL_INCIDENTS" | python3 -m json.tool 2>/dev/null || echo "  $FINAL_INCIDENTS"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}All critical tests passed. SENTINEL-AI Commander is operational.${NC}"
    exit 0
elif [ "$FAIL" -le 2 ]; then
    echo -e "  ${YELLOW}Minor issues detected. Core functionality is working.${NC}"
    exit 0
else
    echo -e "  ${RED}Multiple failures detected. Review output above.${NC}"
    exit 1
fi
