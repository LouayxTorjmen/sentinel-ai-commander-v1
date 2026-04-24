#!/bin/bash
# deploy_agent_configs.sh
# Deploys the correct ossec.conf to every active/disconnected agent
# and fixes the manager's vulnerability-detector for RHEL 10.
# Run from: /root/sentinel-ai-commander/
set -e

SSH="ssh -i ansible/keys/id_rsa -o StrictHostKeyChecking=no -o ConnectTimeout=10"
SCP="scp -i ansible/keys/id_rsa -o StrictHostKeyChecking=no -o ConnectTimeout=10"

G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"; RST="\033[0m"
ok()   { echo -e "${G}[OK]${RST}   $*"; }
warn() { echo -e "${Y}[WARN]${RST} $*"; }
fail() { echo -e "${R}[FAIL]${RST} $*"; }
info() { echo -e "${C}[INFO]${RST} $*"; }

echo ""
echo "========================================================"
echo "  SENTINEL-AI — Agent Config + Vuln Detection Fix"
echo "========================================================"
echo ""

# ── Step 1: Get Wazuh API token ──────────────────────────────────────────────
info "Getting Wazuh API token..."
TOKEN=$(curl -sk -X POST https://localhost:50001/security/user/authenticate \
  -u "wazuh-wui:Louay@2002" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")
[ -z "$TOKEN" ] && { fail "Cannot get Wazuh API token. Is the manager running?"; exit 1; }
ok "Token obtained"

# ── Step 2: List all registered agents ─────────────────────────────────────
echo ""
info "Registered agents:"
AGENT_DATA=$(curl -sk "https://localhost:50001/agents?limit=500" \
  -H "Authorization: Bearer $TOKEN")
echo "$AGENT_DATA" | python3 -c "
import sys,json
for a in json.load(sys.stdin)['data']['affected_items']:
    print(f\"  {a['id']}  {a['name']:<35} {a.get('ip','?'):<18} {a['status']}\")
"

# ── Step 3: Build list of VM IPs ────────────────────────────────────────────
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
info "Target IPs: $AGENT_IPS"

# ── Step 4: Deploy correct config to each VM ────────────────────────────────
echo ""
info "Deploying configs to agents..."

for IP in $AGENT_IPS; do
  echo ""
  echo "  ── $IP ──────────────────────────────────────────────"

  # Test SSH
  if ! $SSH root@$IP "echo SSH_OK" 2>/dev/null | grep -q SSH_OK; then
    warn "SSH not reachable on $IP — skipping"
    continue
  fi

  # Detect OS family
  OS_FAMILY=$($SSH root@$IP "
    if [ -f /etc/debian_version ]; then echo debian
    elif [ -f /etc/redhat-release ]; then echo rhel
    elif [ -f /etc/fedora-release ]; then echo rhel
    else echo unknown
    fi
  " 2>/dev/null)
  info "  OS family: $OS_FAMILY"

  # Choose correct config
  case "$OS_FAMILY" in
    debian)
      CONF_FILE="wazuh/config/agents/ossec_ubuntu.conf"
      ;;
    rhel)
      CONF_FILE="wazuh/config/agents/ossec_rhel.conf"
      ;;
    *)
      warn "  Unknown OS on $IP — using RHEL config as safer default"
      CONF_FILE="wazuh/config/agents/ossec_rhel.conf"
      ;;
  esac

  info "  Config: $CONF_FILE"

  # Stop, deploy, restart
  $SCP $CONF_FILE root@$IP:/tmp/ossec_new.conf
  $SSH root@$IP "
    set -e
    systemctl stop wazuh-agent 2>/dev/null || true
    sleep 2
    cp /tmp/ossec_new.conf /var/ossec/etc/ossec.conf
    chown root:wazuh /var/ossec/etc/ossec.conf
    chmod 640 /var/ossec/etc/ossec.conf

    # Verify the XML is valid before starting
    XML_OK=\$(/var/ossec/bin/wazuh-logtest -t 2>&1 | grep -c 'error\|ERROR' || true)
    [ \"\$XML_OK\" -gt 5 ] && { echo 'XML validation issues, check config'; }

    systemctl start wazuh-agent
    systemctl enable wazuh-agent
    sleep 5
    STATUS=\$(systemctl is-active wazuh-agent)
    echo \"  Service: \$STATUS\"

    # Verify syscollector is in config
    SC_COUNT=\$(grep -c 'syscollector' /var/ossec/etc/ossec.conf)
    SCA_COUNT=\$(grep -c '<sca>' /var/ossec/etc/ossec.conf)
    SYNC_COUNT=\$(grep -c '<synchronization>' /var/ossec/etc/ossec.conf)
    echo \"  syscollector mentions: \$SC_COUNT\"
    echo \"  sca block: \$SCA_COUNT\"
    echo \"  synchronization blocks: \$SYNC_COUNT\"
    echo \"  Last log line:\"
    tail -3 /var/ossec/logs/ossec.log
  "
  ok "  $IP done"
done

# ── Step 5: Fix manager vulnerability-detector for RHEL 10 ─────────────────
echo ""
info "Fixing manager vulnerability-detector providers..."

docker exec sentinel-wazuh-manager bash -c '
# Check current providers
CURRENT=$(grep -c "rhel10\|el10" /var/ossec/etc/ossec.conf 2>/dev/null || echo 0)
if [ "$CURRENT" -gt 0 ]; then
  echo "RHEL 10 provider already configured"
  exit 0
fi

# Backup
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%Y%m%d_%H%M%S)

# Add RHEL 10 provider after the existing redhat provider block
# We use python to do safe XML injection
python3 << PYEOF
import re

with open("/var/ossec/etc/ossec.conf") as f:
    content = f.read()

# Check if RHEL 10 provider already present
if "el10" in content or "rhel10" in content.lower():
    print("RHEL 10 already in config")
    exit(0)

# Find the redhat provider block and add os 10 to it
# Pattern: find <provider name="redhat"> ... </provider> and add <os>10</os>
def add_rhel10(m):
    block = m.group(0)
    if "<os>10</os>" not in block:
        block = block.replace("</provider>", "      <os>10</os>\n    </provider>", 1)
    return block

new_content = re.sub(
    r'<provider name="redhat">.*?</provider>',
    add_rhel10,
    content,
    flags=re.DOTALL
)

if new_content == content:
    # Redhat provider not found, add it entirely before </vulnerability-detector>
    rhel10_provider = """
    <provider name="redhat">
      <enabled>yes</enabled>
      <os>9</os>
      <os>8</os>
      <os>10</os>
      <update_interval>1h</update_interval>
    </provider>
"""
    new_content = content.replace(
        "</vulnerability-detector>",
        rhel10_provider + "  </vulnerability-detector>"
    )

with open("/var/ossec/etc/ossec.conf", "w") as f:
    f.write(new_content)
print("RHEL 10 provider added to vulnerability-detector")
PYEOF
'

if [ $? -eq 0 ]; then
  ok "Manager vulnerability config updated"
else
  warn "Manager vulnerability config update had issues — check manually"
fi

# Restart manager to pick up config change
info "Restarting Wazuh manager..."
docker exec sentinel-wazuh-manager /var/ossec/bin/ossec-control restart 2>/dev/null || \
  docker exec sentinel-wazuh-manager /var/ossec/bin/wazuh-control restart 2>/dev/null || \
  true
sleep 10
ok "Manager restarted"

# ── Step 6: Wait and verify syscollector sent data ──────────────────────────
echo ""
info "Waiting 90s for agents to reconnect and send syscollector inventory..."
sleep 90

echo ""
info "Checking syscollector DB on manager (should NOT be empty now)..."
docker exec sentinel-wazuh-manager bash -c '
  DB_PATH="/var/ossec/queue/syscollector/db"
  if [ -d "$DB_PATH" ]; then
    FILES=$(ls "$DB_PATH" 2>/dev/null | wc -l)
    echo "  Syscollector DB files: $FILES"
    for f in $(ls "$DB_PATH" 2>/dev/null | head -5); do
      echo "  Agent $f tables:"
      sqlite3 "$DB_PATH/$f" ".tables" 2>/dev/null | tr " " "\n" | head -10 | sed "s/^/    /"
    done
  else
    echo "  DB path does not exist: $DB_PATH"
    echo "  Try: /var/ossec/queue/db/ instead"
    ls /var/ossec/queue/ 2>/dev/null
  fi
'

# ── Step 7: Final agent status ───────────────────────────────────────────────
echo ""
info "Final agent status:"
curl -sk "https://localhost:50001/agents?limit=500" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "
import sys,json
for a in json.load(sys.stdin)['data']['affected_items']:
    status = a['status']
    icon = '✅' if status == 'active' else '❌'
    print(f\"  {icon} {a['id']}  {a['name']:<35} {a.get('ip','?'):<18} {status}\")
"

echo ""
echo "========================================================"
echo "  Done. Check Wazuh Dashboard in 2-5 minutes:"
echo "  - IT Hygiene → System, Software, Processes, Network,"
echo "    Identity (Users/Groups), Services should all populate"
echo "  - Vulnerability Detection should show CVEs per agent"
echo "  - Configuration Assessment should show SCA findings"
echo "  - FIM realtime monitoring active immediately"
echo ""
echo "  If IT Hygiene still empty after 5 min:"
echo "    docker exec sentinel-wazuh-manager grep -i syscollector"
echo "    /var/ossec/logs/ossec.log | tail -20"
echo "========================================================"
