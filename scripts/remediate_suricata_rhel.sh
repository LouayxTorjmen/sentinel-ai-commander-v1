#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# remediate_suricata_rhel.sh — Fix RHEL 10 / Rocky 10 Suricata install
# ═══════════════════════════════════════════════════════════════════════
# The generic script fails on:
#  - Unregistered RHEL (no EPEL access)       → use Rocky 10 repos directly
#  - Rocky 10 + Suricata 8.0 copr (DPDK 26 deps missing) → use copr for Suricata 7.0
#                                                           OR install dpdk from crb
# Strategy per host:
#   1. Detect real distro (Rocky vs actual RHEL vs Alma)
#   2. Ensure crb repo enabled (for deps)
#   3. Try Suricata from EPEL 10 first (no DPDK issue)
#   4. Fallback: Suricata 7.0 copr (no DPDK 26 dep)
#   5. Fallback: install dpdk first, then 8.0 copr
#   6. Configure, update rules, start, integrate with Wazuh
# ═══════════════════════════════════════════════════════════════════════

set +u

SENTINEL_DIR="${SENTINEL_DIR:-$HOME/sentinel-ai-commander}"
SSH_KEY="${SSH_KEY:-$SENTINEL_DIR/ansible/keys/id_rsa}"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"
B="\033[1m"; DIM="\033[2m"; RST="\033[0m"

TARGETS=(
  "auto-victim2-rhel|192.168.49.145"
  "rhel-agent2|192.168.49.129"
)

banner() {
    echo -e "${C}╔════════════════════════════════════════════════════════════════╗"
    echo -e "║  🔧  RHEL/Rocky Suricata Remediation                           ║"
    echo -e "╚════════════════════════════════════════════════════════════════╝${RST}"
    echo ""
    echo -e "  Targets:"
    for t in "${TARGETS[@]}"; do
        IFS='|' read -r name ip <<< "$t"
        echo -e "    ${R}●${RST} $name ($ip)"
    done
    echo ""
}

confirm() {
    echo -ne "  ${Y}?${RST} $1 [y/N] "
    read -r a
    [[ "$a" =~ ^[Yy]$ ]]
}

# ── Remote script ──────────────────────────────────────────────────────
REMOTE_SCRIPT='
set -e
log() { echo "[$(date +%H:%M:%S)] $*"; }

# --- 1. Detect interface ---
IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP "dev \K\S+" | head -1)
[ -z "$IFACE" ] && { log "ERROR: no interface"; exit 2; }
SUBNET=$(ip -4 addr show "$IFACE" | grep -oP "inet \K[0-9.]+/[0-9]+" | head -1)
log "Interface: $IFACE  Subnet: $SUBNET"

# --- 2. Detect real distro ---
DISTRO=unknown
if [ -f /etc/rocky-release ]; then
    DISTRO=rocky
    REL_VERSION=$(grep -oP "release \K[0-9]+" /etc/rocky-release | head -1)
elif [ -f /etc/almalinux-release ]; then
    DISTRO=alma
    REL_VERSION=$(grep -oP "release \K[0-9]+" /etc/almalinux-release | head -1)
elif [ -f /etc/redhat-release ]; then
    DISTRO=rhel
    REL_VERSION=$(grep -oP "release \K[0-9]+" /etc/redhat-release | head -1)
fi
log "Distro: $DISTRO $REL_VERSION"

# --- 3. Enable CRB / PowerTools (for dpdk and other deps) ---
log "Enabling CRB repo (if applicable)..."
dnf config-manager --set-enabled crb 2>/dev/null \
    || dnf config-manager --set-enabled powertools 2>/dev/null \
    || dnf config-manager --set-enabled codeready-builder-for-rhel-$REL_VERSION-x86_64-rpms 2>/dev/null \
    || log "  (no CRB-like repo available)"

# --- 4. Try to install Suricata via various strategies ---

install_success=no

# Strategy A: EPEL 10
if [ "$install_success" = "no" ]; then
    log "Strategy A: Try EPEL (epel-release + suricata from EPEL)..."
    # For unregistered RHEL 10, install EPEL rpm directly from the Fedora project
    if ! rpm -q epel-release >/dev/null 2>&1; then
        dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${REL_VERSION}.noarch.rpm" 2>&1 | tail -3 || true
    fi
    if rpm -q epel-release >/dev/null 2>&1; then
        # Remove the copr repo so EPEL wins priority for suricata
        dnf -y remove suricata 2>/dev/null || true
        # Try EPEL suricata
        if dnf install -y --repo=epel suricata jq 2>&1 | tail -3; then
            if command -v suricata >/dev/null 2>&1; then
                log "  ✓ Installed via EPEL"
                install_success=yes
            fi
        fi
    else
        log "  EPEL not available"
    fi
fi

# Strategy B: Install DPDK first then retry 8.0 copr
if [ "$install_success" = "no" ]; then
    log "Strategy B: Install dpdk then retry copr Suricata 8.0..."
    dnf install -y dpdk dpdk-devel 2>&1 | tail -3 || true
    if dnf install -y suricata jq 2>&1 | tail -3; then
        if command -v suricata >/dev/null 2>&1; then
            log "  ✓ Installed with DPDK"
            install_success=yes
        fi
    fi
fi

# Strategy C: Suricata 7.0 copr (older, no DPDK 26 dep)
if [ "$install_success" = "no" ]; then
    log "Strategy C: Try Suricata 7.0 copr..."
    # Disable 8.0 copr
    dnf copr disable -y @oisf/suricata-8.0 2>/dev/null || true
    dnf copr enable  -y @oisf/suricata-7.0 2>&1 | tail -2 || true
    if dnf install -y suricata jq 2>&1 | tail -3; then
        if command -v suricata >/dev/null 2>&1; then
            log "  ✓ Installed via copr 7.0"
            install_success=yes
        fi
    fi
fi

# Strategy D: Suricata 6.0 copr
if [ "$install_success" = "no" ]; then
    log "Strategy D: Try Suricata 6.0 copr..."
    dnf copr disable -y @oisf/suricata-7.0 2>/dev/null || true
    dnf copr enable  -y @oisf/suricata-6.0 2>&1 | tail -2 || true
    if dnf install -y suricata jq 2>&1 | tail -3; then
        if command -v suricata >/dev/null 2>&1; then
            log "  ✓ Installed via copr 6.0"
            install_success=yes
        fi
    fi
fi

if [ "$install_success" = "no" ]; then
    log "✗ ALL install strategies failed"
    log "Enabled repos:"
    dnf repolist --enabled 2>&1 | head -15
    exit 5
fi

log "Installed: $(suricata -V 2>&1 | head -1)"

# --- 5. Patch suricata.yaml ---
CONFIG=/etc/suricata/suricata.yaml
[ ! -f "$CONFIG" ] && { log "ERROR: $CONFIG not found"; exit 6; }
[ ! -f "${CONFIG}.sentinel-bak" ] && cp "$CONFIG" "${CONFIG}.sentinel-bak"

python3 <<PYEOF
import re
path = "$CONFIG"
iface = "$IFACE"
subnet = "$SUBNET"

with open(path) as f:
    content = f.read()

# Fix af-packet interface
lines = content.split("\n")
in_afp = False
for i, line in enumerate(lines):
    if line.strip().startswith("af-packet:"):
        in_afp = True
        continue
    if in_afp:
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            break
        m = re.match(r"(\s*-?\s*interface:\s*)(\S+)", line)
        if m:
            lines[i] = f"{m.group(1)}{iface}"
            print(f"  af-packet interface -> {iface}")
            break
content = "\n".join(lines)

# Add subnet to HOME_NET
m = re.search(r"(HOME_NET:\s*)([\"\x27])(\[.*?\])(\2)", content)
if m and subnet and subnet not in m.group(3):
    new_val = m.group(3).rstrip("]") + f",{subnet}]"
    content = content[:m.start(3)] + new_val + content[m.end(3):]
    print(f"  Added {subnet} to HOME_NET")

with open(path, "w") as f:
    f.write(content)
PYEOF

# --- 6. Update sources, pull ET Open rules ---
log "Running suricata-update update-sources..."
suricata-update update-sources -q 2>&1 | tail -3 || true
log "Running suricata-update (downloading rules)..."
suricata-update -q 2>&1 | tail -3 || true

RULE_COUNT=$(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)
log "Rules loaded: $RULE_COUNT"

# --- 7. Validate config ---
log "Validating config..."
suricata -T -c "$CONFIG" -i "$IFACE" 2>&1 | tail -5 || log "  (validation non-zero, may still work)"

# --- 8. Start service ---
systemctl daemon-reload
systemctl enable suricata 2>&1 | tail -1
systemctl restart suricata
sleep 3

if systemctl is-active --quiet suricata; then
    log "✓ Suricata active"
else
    log "✗ Suricata failed — journalctl:"
    journalctl -u suricata -n 15 --no-pager
    exit 7
fi

# --- 9. Wazuh integration ---
OSSEC_CONF=/var/ossec/etc/ossec.conf
if [ -f "$OSSEC_CONF" ]; then
    if grep -q "/var/log/suricata/eve.json" "$OSSEC_CONF"; then
        log "Wazuh already tails eve.json"
    else
        [ ! -f "${OSSEC_CONF}.sentinel-bak" ] && cp "$OSSEC_CONF" "${OSSEC_CONF}.sentinel-bak"
        python3 <<PYEOF
path = "$OSSEC_CONF"
block = """  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>

"""
with open(path) as f:
    content = f.read()
if "</ossec_config>" in content:
    content = content.replace("</ossec_config>", block + "</ossec_config>")
    with open(path, "w") as f:
        f.write(content)
    print("  Localfile block added")
PYEOF
        log "Restarting wazuh-agent..."
        systemctl restart wazuh-agent
        sleep 2
    fi
fi

# --- 10. Verify ---
log "──── Verification ────"
log "Suricata:     $(systemctl is-active suricata)"
log "Wazuh agent:  $(systemctl is-active wazuh-agent 2>/dev/null || echo n/a)"
log "eve.json:     $(ls -la /var/log/suricata/eve.json 2>&1 | head -1)"
log "Rules:        $(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)"

sleep 3
S1=$(stat -c%s /var/log/suricata/eve.json 2>/dev/null || echo 0)
sleep 3
S2=$(stat -c%s /var/log/suricata/eve.json 2>/dev/null || echo 0)
if [ "$S2" -gt "$S1" ]; then
    log "✓ eve.json growing ($S1 → $S2 bytes)"
elif [ "$S1" -gt 0 ]; then
    log "  eve.json has $S1 bytes (not growing in 3s — may be idle)"
else
    log "⚠ eve.json empty — run some traffic to verify"
fi

log "DONE"
'

remediate_host() {
    local name="$1" ip="$2"
    echo ""
    echo -e "${B}${C}━━━ $name ${DIM}($ip)${RST}"

    if ! confirm "Remediate $name?"; then
        echo -e "  ${DIM}Skipped${RST}"
        return
    fi

    if ! ssh $SSH_OPTS "root@$ip" "echo ok" </dev/null >/dev/null 2>&1; then
        echo -e "  ${R}✗ SSH unreachable${RST}"
        return
    fi

    echo -e "  ${C}→ Executing remediation (may try multiple install strategies)...${RST}"
    echo ""

    ssh $SSH_OPTS "root@$ip" "bash -s" <<< "$REMOTE_SCRIPT" 2>&1 | sed 's/^/    /'
    local rc=${PIPESTATUS[0]}

    echo ""
    if [ "$rc" -eq 0 ]; then
        echo -e "  ${G}${B}✓ Remediation complete for $name${RST}"
    else
        echo -e "  ${R}${B}✗ Exited with code $rc${RST}"
    fi
}

main() {
    banner
    if ! confirm "Proceed with RHEL remediation?"; then
        echo "Aborted."
        exit 0
    fi

    for t in "${TARGETS[@]}"; do
        IFS='|' read -r name ip <<< "$t"
        remediate_host "$name" "$ip"
    done

    echo ""
    echo -e "${C}Done.${RST} Re-run audit to verify:"
    echo -e "  ${B}bash ~/sentinel-ai-commander/scripts/audit_suricata.sh${RST}"
}

main "$@"
