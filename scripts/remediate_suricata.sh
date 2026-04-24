#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# remediate_suricata.sh — Fix/install Suricata on broken agents
# ═══════════════════════════════════════════════════════════════════════
# Per host, based on audit results, does one of:
#   A) FULL INSTALL (host has no Suricata):
#      - detect OS, install Suricata via apt or dnf
#      - then proceeds to B
#   B) REPAIR (host has Suricata but broken config):
#      - detect real network interface
#      - patch /etc/suricata/suricata.yaml (af-packet interface)
#      - run suricata-update update-sources + suricata-update
#      - enable + start suricata
#      - add <localfile> for eve.json to /var/ossec/etc/ossec.conf
#      - restart wazuh-agent
#      - verify
#
# Interactive by default — asks before each host.
# Pass --auto to skip confirmations.
# ═══════════════════════════════════════════════════════════════════════

set +u

SENTINEL_DIR="${SENTINEL_DIR:-$HOME/sentinel-ai-commander}"
SSH_KEY="${SSH_KEY:-$SENTINEL_DIR/ansible/keys/id_rsa}"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"
B="\033[1m"; DIM="\033[2m"; RST="\033[0m"

AUTO_MODE=false
[ "${1:-}" = "--auto" ] && AUTO_MODE=true

# ── Targets: name|ip|action ────────────────────────────────────────────
# action is 'install' (no suricata) or 'repair' (broken config)
TARGETS=(
  "auto-victim1-ubuntu|192.168.49.128|repair"
  "auto-victim2-rhel|192.168.49.145|install"
  "rhel-agent2|192.168.49.129|install"
  "ubuntu-agent-2|192.168.49.130|repair"
)

# ── Helpers ────────────────────────────────────────────────────────────
banner() {
    echo -e "${C}╔════════════════════════════════════════════════════════════════╗"
    echo -e "║  🔧  Suricata Remediation — SENTINEL-AI Commander              ║"
    echo -e "╚════════════════════════════════════════════════════════════════╝${RST}"
    echo ""
    echo -e "  Hosts to remediate:  ${B}${#TARGETS[@]}${RST}"
    for t in "${TARGETS[@]}"; do
        IFS='|' read -r name ip action <<< "$t"
        local color=$Y
        [ "$action" = "install" ] && color=$R
        echo -e "    ${color}●${RST} $name ($ip) — $action"
    done
    echo ""
    if ! $AUTO_MODE; then
        echo -e "  ${DIM}Running in interactive mode — will confirm before each host.${RST}"
        echo -e "  ${DIM}Use --auto to skip confirmations.${RST}"
    else
        echo -e "  ${Y}Running in AUTO mode — no confirmations.${RST}"
    fi
    echo ""
}

confirm() {
    $AUTO_MODE && return 0
    local prompt="$1"
    echo -ne "  ${Y}?${RST} $prompt [y/N] "
    read -r answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

ssh_run() {
    local ip="$1"
    shift
    ssh $SSH_OPTS "root@$ip" "$@" </dev/null
}

# ─────────────────────────────────────────────────────────────────────
# The remote remediation script — handles both install and repair.
# Takes INTERFACE as first argument (empty string = auto-detect).
# Idempotent: safe to re-run.
# ─────────────────────────────────────────────────────────────────────
REMOTE_SCRIPT=$(cat <<'REMOTE_EOF'
set -e
INTERFACE_HINT="${1:-}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# ── 1. Detect interface ──
if [ -n "$INTERFACE_HINT" ]; then
    IFACE="$INTERFACE_HINT"
else
    IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
fi
if [ -z "$IFACE" ]; then
    log "ERROR: could not detect network interface"
    exit 2
fi
log "Using interface: $IFACE"

# ── 2. Detect subnet for HOME_NET ──
SUBNET=$(ip -4 addr show "$IFACE" | grep -oP 'inet \K[0-9.]+/[0-9]+' | head -1)
log "Subnet for HOME_NET: $SUBNET"

# ── 3. Detect OS family ──
if command -v apt-get >/dev/null 2>&1; then
    OS_FAMILY=debian
elif command -v dnf >/dev/null 2>&1; then
    OS_FAMILY=rhel
elif command -v yum >/dev/null 2>&1; then
    OS_FAMILY=rhel_yum
else
    log "ERROR: unknown package manager"
    exit 3
fi
log "OS family: $OS_FAMILY"

# ── 4. Install Suricata if missing ──
if ! command -v suricata >/dev/null 2>&1; then
    log "Suricata not installed — installing..."
    case "$OS_FAMILY" in
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq software-properties-common
            if ! apt-cache policy | grep -q 'oisf/suricata-stable'; then
                add-apt-repository -y ppa:oisf/suricata-stable
                apt-get update -qq
            fi
            apt-get install -y -qq suricata jq
            ;;
        rhel)
            dnf install -y -q epel-release dnf-plugins-core
            # copr for suricata (more recent than EPEL)
            if ! dnf copr list --enabled 2>/dev/null | grep -q oisf; then
                dnf copr enable -y @oisf/suricata-8.0 2>&1 | tail -3 || \
                dnf copr enable -y @oisf/suricata-7.0 2>&1 | tail -3
            fi
            dnf install -y -q suricata jq
            ;;
        rhel_yum)
            yum install -y -q epel-release
            yum install -y -q suricata jq
            ;;
    esac
    log "Suricata install complete: $(suricata -V 2>&1 | head -1)"
else
    log "Suricata already installed: $(suricata -V 2>&1 | head -1)"
fi

# ── 5. Patch suricata.yaml — af-packet interface ──
CONFIG=/etc/suricata/suricata.yaml
if [ ! -f "$CONFIG" ]; then
    log "ERROR: $CONFIG not found after install"
    exit 4
fi

# Backup once
[ ! -f "${CONFIG}.sentinel-bak" ] && cp "$CONFIG" "${CONFIG}.sentinel-bak"

# Use Python for YAML-safe edit (available on all our target distros)
python3 <<PYEOF
import re, sys
path = "$CONFIG"
iface = "$IFACE"
subnet = "$SUBNET"

with open(path) as f:
    content = f.read()

# Fix af-packet interface — it's the first 'interface:' under 'af-packet:'
# af-packet:
#   - interface: eth0     <-- change this
def fix_af_packet(content, new_iface):
    lines = content.split('\n')
    in_afp = False
    changed = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('af-packet:'):
            in_afp = True
            continue
        if in_afp:
            # Stop if we hit another top-level section (no leading space, ends with :)
            if line and not line[0].isspace() and line.rstrip().endswith(':'):
                break
            m = re.match(r'(\s*-?\s*interface:\s*)(\S+)', line)
            if m:
                if m.group(2) != new_iface:
                    lines[i] = f"{m.group(1)}{new_iface}"
                    changed = True
                break
    return '\n'.join(lines), changed

content, changed = fix_af_packet(content, iface)
if changed:
    print(f"  Patched af-packet interface -> {iface}")
else:
    print(f"  af-packet interface already {iface}")

# HOME_NET — make sure this subnet is included
# Look for: HOME_NET: "[...]"
m = re.search(r'(HOME_NET:\s*)(["\'])(\[.*?\])(\2)', content)
if m and subnet and subnet not in m.group(3):
    # Insert subnet into the existing array
    new_val = m.group(3).rstrip(']') + f',{subnet}]'
    content = content[:m.start(3)] + new_val + content[m.end(3):]
    print(f"  Added {subnet} to HOME_NET")

with open(path, 'w') as f:
    f.write(content)
PYEOF

# ── 6. Update sources + pull ET Open rules ──
log "Running suricata-update update-sources..."
suricata-update update-sources -q 2>&1 | tail -3 || true

log "Running suricata-update (this downloads ~50k rules, takes a moment)..."
suricata-update -q 2>&1 | tail -3 || true

RULE_COUNT=$(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)
log "Rules loaded: $RULE_COUNT"

# ── 7. Validate config before starting ──
log "Validating suricata config..."
if ! suricata -T -c "$CONFIG" -i "$IFACE" 2>&1 | tail -5; then
    log "WARNING: config validation returned non-zero, but may still work"
fi

# ── 8. Enable + start service ──
systemctl daemon-reload
systemctl enable suricata 2>&1 | tail -1
systemctl restart suricata
sleep 3

if systemctl is-active --quiet suricata; then
    log "✓ Suricata service is active"
else
    log "✗ Suricata FAILED to start — last 15 journal lines:"
    journalctl -u suricata -n 15 --no-pager
    exit 5
fi

# ── 9. Add Wazuh localfile block for eve.json ──
OSSEC_CONF=/var/ossec/etc/ossec.conf
if [ -f "$OSSEC_CONF" ]; then
    if grep -q "/var/log/suricata/eve.json" "$OSSEC_CONF"; then
        log "Wazuh already configured to tail eve.json"
    else
        log "Adding <localfile> for eve.json to ossec.conf..."
        # Backup once
        [ ! -f "${OSSEC_CONF}.sentinel-bak" ] && cp "$OSSEC_CONF" "${OSSEC_CONF}.sentinel-bak"
        # Insert before </ossec_config>
        python3 <<PYEOF
path = "$OSSEC_CONF"
block = """  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>

"""
with open(path) as f:
    content = f.read()
if '</ossec_config>' in content:
    content = content.replace('</ossec_config>', block + '</ossec_config>')
    with open(path, 'w') as f:
        f.write(content)
    print("  Localfile block added")
else:
    print("  WARNING: </ossec_config> not found — ossec.conf may be malformed")
PYEOF
        log "Restarting wazuh-agent..."
        systemctl restart wazuh-agent
        sleep 2
    fi
else
    log "NOTE: no Wazuh agent on this host — skipping ossec.conf edit"
fi

# ── 10. Verify ──
log "──── Verification ────"
log "Suricata: $(systemctl is-active suricata)"
log "Wazuh agent: $(systemctl is-active wazuh-agent 2>/dev/null || echo 'n/a')"
log "eve.json: $(ls -la /var/log/suricata/eve.json 2>&1 | head -1)"
log "Rules loaded: $(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)"

# Give it a moment and check eve.json is growing
sleep 3
SIZE1=$(stat -c%s /var/log/suricata/eve.json 2>/dev/null || echo 0)
sleep 3
SIZE2=$(stat -c%s /var/log/suricata/eve.json 2>/dev/null || echo 0)
if [ "$SIZE2" -gt "$SIZE1" ]; then
    log "✓ eve.json is growing ($SIZE1 → $SIZE2 bytes)"
elif [ "$SIZE1" -gt 0 ]; then
    log "⚠ eve.json has $SIZE1 bytes but not growing in 3s (may be idle — run a scan to verify)"
else
    log "⚠ eve.json is empty — check 'journalctl -u suricata' for errors"
fi

log "DONE"
REMOTE_EOF
)

# ─────────────────────────────────────────────────────────────────────
# Per-host driver
# ─────────────────────────────────────────────────────────────────────
remediate_host() {
    local name="$1"
    local ip="$2"
    local action="$3"

    echo ""
    echo -e "${B}${C}━━━ $name ${DIM}($ip, action: $action)${RST}"

    if ! confirm "Remediate $name?"; then
        echo -e "  ${DIM}Skipped${RST}"
        return
    fi

    # SSH reachability
    if ! ssh_run "$ip" "echo ok" >/dev/null 2>&1; then
        echo -e "  ${R}✗ SSH unreachable — skipping${RST}"
        return
    fi

    # Pre-detect interface on remote side and show user
    local iface
    iface=$(ssh_run "$ip" "ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \\K\\S+' | head -1")
    echo -e "  ${DIM}  Remote interface: $iface${RST}"

    # Execute remediation
    echo -e "  ${C}→ Executing remediation...${RST}"
    echo ""

    # Stream output live so the user can watch long-running installs / rule downloads
    ssh $SSH_OPTS "root@$ip" "bash -s -- '$iface'" <<< "$REMOTE_SCRIPT" 2>&1 | sed 's/^/    /'
    local rc=${PIPESTATUS[0]}

    echo ""
    if [ "$rc" -eq 0 ]; then
        echo -e "  ${G}${B}✓ Remediation complete for $name${RST}"
    else
        echo -e "  ${R}${B}✗ Remediation exited with code $rc${RST}"
    fi
}

# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────
main() {
    banner

    if ! $AUTO_MODE; then
        if ! confirm "Proceed with remediation of ${#TARGETS[@]} hosts?"; then
            echo "Aborted."
            exit 0
        fi
    fi

    for t in "${TARGETS[@]}"; do
        IFS='|' read -r name ip action <<< "$t"
        remediate_host "$name" "$ip" "$action"
    done

    echo ""
    echo -e "${C}╔════════════════════════════════════════════════════════════════╗"
    echo -e "║  All done                                                      ║"
    echo -e "╚════════════════════════════════════════════════════════════════╝${RST}"
    echo ""
    echo -e "  Next step: re-run the audit to confirm all hosts are HEALTHY:"
    echo -e "    ${B}bash ~/sentinel-ai-commander/scripts/audit_suricata.sh${RST}"
    echo ""
}

main "$@"
