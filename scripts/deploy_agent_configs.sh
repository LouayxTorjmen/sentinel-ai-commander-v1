#!/bin/bash
# =============================================================================
#  deploy_agent_configs.sh
#  Push the canonical SOC ossec.conf template (Ubuntu or RHEL) to Wazuh agents
#  and substitute the manager IP/port from .env.
#
#  Usage:
#    bash scripts/deploy_agent_configs.sh              # fleet-wide (all agents)
#    bash scripts/deploy_agent_configs.sh 192.168.1.5  # only that IP
#
#  Credentials and manager IP/port are read from .env in the repo root.
#  Safe to re-run. Silently skips unreachable hosts (fleet mode) or fails
#  fast with a clear error (single-IP mode, used from enroll.py).
# =============================================================================
set -u

SSH="ssh -i ansible/keys/id_rsa -o StrictHostKeyChecking=no -o ConnectTimeout=10"
SCP="scp -i ansible/keys/id_rsa -o StrictHostKeyChecking=no -o ConnectTimeout=10"

G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"; RST="\033[0m"
ok()   { echo -e "${G}[OK]${RST}   $*"; }
warn() { echo -e "${Y}[WARN]${RST} $*"; }
fail() { echo -e "${R}[FAIL]${RST} $*"; }
info() { echo -e "${C}[INFO]${RST} $*"; }

# ── Locate repo root (parent of scripts/) ──────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || { fail "Cannot cd to repo root"; exit 1; }

# ── Load .env ──────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    fail ".env not found in $REPO_ROOT"
    exit 1
fi
set -a
# shellcheck disable=SC1091
source .env
set +a

# Required env vars
: "${WAZUH_API_USER:?WAZUH_API_USER not set in .env}"
: "${WAZUH_API_PASSWORD:?WAZUH_API_PASSWORD not set in .env}"

# Manager IP/port for the template (agents connect to THIS)
# WAZUH_MANAGER_EXTERNAL_IP is the host-LAN IP agents use to reach the manager.
# Fall back to a sensible internal default if unset.
MANAGER_IP="${WAZUH_MANAGER_EXTERNAL_IP:-${WAZUH_MANAGER_IP:-172.31.70.13}}"
MANAGER_PORT="${PORT_WAZUH_AGENT_COMM_TCP:-50041}"

# ── Parse target (optional single IP) ──────────────────────────────────
SINGLE_IP="${1:-}"

echo ""
echo "========================================================"
echo "  SENTINEL-AI — Deploy agent SOC config"
echo "  Manager: ${MANAGER_IP}:${MANAGER_PORT}"
if [ -n "$SINGLE_IP" ]; then
    echo "  Target:  single IP ${SINGLE_IP}"
else
    echo "  Target:  all registered agents"
fi
echo "========================================================"
echo ""

# ── Get Wazuh API token ────────────────────────────────────────────────
info "Authenticating to Wazuh API..."
TOKEN=$(curl -sk -X POST "https://localhost:${PORT_WAZUH_API:-50001}/security/user/authenticate" \
  -u "${WAZUH_API_USER}:${WAZUH_API_PASSWORD}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('token',''))" 2>/dev/null)

if [ -z "$TOKEN" ]; then
    fail "Cannot get Wazuh API token. Is the manager running and .env correct?"
    exit 1
fi
ok "Token obtained"

# ── Build the IP list ──────────────────────────────────────────────────
if [ -n "$SINGLE_IP" ]; then
    AGENT_IPS="$SINGLE_IP"
else
    AGENT_DATA=$(curl -sk "https://localhost:${PORT_WAZUH_API:-50001}/agents?limit=500" \
      -H "Authorization: Bearer $TOKEN")
    echo ""
    info "Registered agents:"
    echo "$AGENT_DATA" | python3 -c "
import sys,json
for a in json.load(sys.stdin)['data']['affected_items']:
    print(f\"  {a['id']}  {a['name']:<35} {a.get('ip','?'):<18} {a['status']}\")
"
    AGENT_IPS=$(echo "$AGENT_DATA" | python3 -c "
import sys,json
agents = json.load(sys.stdin)['data']['affected_items']
ips = set()
for a in agents:
    ip = a.get('ip','')
    if ip and ip not in ('any','127.0.0.1','') and a.get('id') != '000':
        ips.add(ip)
print(' '.join(sorted(ips)))
")
fi

if [ -z "$AGENT_IPS" ]; then
    warn "No target IPs."
    exit 0
fi

# ── Deploy to each target ──────────────────────────────────────────────
echo ""
info "Deploying SOC config templates..."
OVERALL_RC=0

for IP in $AGENT_IPS; do
    echo ""
    echo "  ── $IP ──────────────────────────────────────────────"

    # SSH check
    if ! $SSH root@"$IP" "echo SSH_OK" 2>/dev/null | grep -q SSH_OK; then
        if [ -n "$SINGLE_IP" ]; then
            fail "SSH not reachable on $IP"
            exit 2
        else
            warn "SSH not reachable on $IP — skipping"
            OVERALL_RC=1
            continue
        fi
    fi

    # OS family detection
    OS_FAMILY=$($SSH root@"$IP" "
        if [ -f /etc/debian_version ]; then echo debian
        elif [ -f /etc/redhat-release ]; then echo rhel
        elif [ -f /etc/fedora-release ]; then echo rhel
        else echo unknown
        fi
    " 2>/dev/null)
    info "  OS family: $OS_FAMILY"

    case "$OS_FAMILY" in
        debian) CONF_FILE="wazuh/config/agents/ossec_ubuntu.conf" ;;
        rhel)   CONF_FILE="wazuh/config/agents/ossec_rhel.conf"   ;;
        *)
            warn "  Unknown OS — defaulting to RHEL template"
            CONF_FILE="wazuh/config/agents/ossec_rhel.conf"
            ;;
    esac
    info "  Config: $CONF_FILE"

    if [ ! -f "$CONF_FILE" ]; then
        fail "  Template file $CONF_FILE missing from repo"
        OVERALL_RC=1
        continue
    fi

    # Render template to a temporary file with the current manager IP/port
    # substituted (the repo templates have 172.31.70.13 / 50041 hardcoded)
    RENDERED=$(mktemp)
    # Replace <address>...</address> and <port>...</port> inside the <server> block
    python3 - "$CONF_FILE" "$RENDERED" "$MANAGER_IP" "$MANAGER_PORT" << 'PYEOF'
import sys, re
src, dst, ip, port = sys.argv[1:5]
with open(src) as f:
    content = f.read()
# Rewrite the <server>...</server> block's address and port
def fix_server(m):
    block = m.group(0)
    block = re.sub(r'<address>[^<]*</address>', f'<address>{ip}</address>', block)
    block = re.sub(r'<port>[^<]*</port>',       f'<port>{port}</port>',    block)
    return block
content = re.sub(r'<server>.*?</server>', fix_server, content, flags=re.DOTALL, count=1)
with open(dst, 'w') as f:
    f.write(content)
PYEOF

    # Ship + install
    $SCP "$RENDERED" root@"$IP":/tmp/ossec_new.conf >/dev/null
    rm -f "$RENDERED"

    $SSH root@"$IP" "
        set -e
        systemctl stop wazuh-agent 2>/dev/null || true
        sleep 2
        cp /tmp/ossec_new.conf /var/ossec/etc/ossec.conf
        chown root:wazuh /var/ossec/etc/ossec.conf 2>/dev/null || chown root:ossec /var/ossec/etc/ossec.conf 2>/dev/null || true
        chmod 640 /var/ossec/etc/ossec.conf
        rm -f /tmp/ossec_new.conf
        systemctl enable wazuh-agent >/dev/null 2>&1 || true
        systemctl start wazuh-agent
        sleep 5
        STATUS=\$(systemctl is-active wazuh-agent)
        echo \"  Service: \$STATUS\"
        SC=\$(grep -c 'syscollector' /var/ossec/etc/ossec.conf)
        SCA=\$(grep -c '<sca>' /var/ossec/etc/ossec.conf)
        echo \"  syscollector mentions: \$SC | sca: \$SCA\"
    "
    if [ $? -eq 0 ]; then
        ok "  $IP done"
    else
        fail "  $IP deploy failed"
        OVERALL_RC=1
    fi
done

echo ""
echo "========================================================"
if [ $OVERALL_RC -eq 0 ]; then
    ok "All targets updated successfully."
else
    warn "Some targets had issues — see output above."
fi
echo ""
echo "  Dashboard check (2-5 min after deploy):"
echo "    IT Hygiene → System/Software/Processes/Network/Users/Groups"
echo "    Endpoint Security → Configuration Assessment (SCA)"
echo "    Endpoint Security → Integrity Monitoring (FIM realtime)"
echo "========================================================"
exit $OVERALL_RC
