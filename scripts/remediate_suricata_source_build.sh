#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# remediate_suricata_source_build.sh
# ═══════════════════════════════════════════════════════════════════════
# Last-resort for RHEL 10 / Rocky 10 where no packaged Suricata works:
# Build Suricata from source (clean, no DPDK dependency).
#
# Uses Suricata 7.0.7 LTS source tarball.
# Build takes ~8-12 minutes per VM on a modest VM.
# Produces: /usr/bin/suricata, /etc/suricata/suricata.yaml, systemd unit
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

SURICATA_VERSION="7.0.7"   # LTS, widely tested

banner() {
    echo -e "${C}╔════════════════════════════════════════════════════════════════╗"
    echo -e "║  🔧  Suricata Source Build Remediation — RHEL 10 / Rocky 10    ║"
    echo -e "╚════════════════════════════════════════════════════════════════╝${RST}"
    echo ""
    echo -e "  ${Y}This builds Suricata ${SURICATA_VERSION} from source.${RST}"
    echo -e "  ${Y}Per-host time: ~8-12 minutes (mostly compilation).${RST}"
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

REMOTE_SCRIPT='
set -e
log() { echo "[$(date +%H:%M:%S)] $*"; }

SURICATA_VER="'"$SURICATA_VERSION"'"

# --- 1. Detect interface and subnet ---
IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP "dev \K\S+" | head -1)
[ -z "$IFACE" ] && { log "ERROR: no interface"; exit 2; }
SUBNET=$(ip -4 addr show "$IFACE" | grep -oP "inet \K[0-9.]+/[0-9]+" | head -1)
log "Interface: $IFACE  Subnet: $SUBNET"

# --- 2. Check if already built ---
if command -v suricata >/dev/null 2>&1; then
    CUR_VER=$(suricata -V 2>&1 | grep -oP "version \K\S+" | head -1)
    log "Suricata ${CUR_VER} already present"
    # Still continue to config+start steps in case install was incomplete
else
    # --- 3. Install build dependencies ---
    log "Installing build dependencies..."
    dnf install -y --nogpgcheck --allowerasing \
        gcc gcc-c++ make automake autoconf libtool pkgconf \
        libpcap-devel pcre2-devel libyaml-devel zlib-devel \
        jansson-devel libcap-ng-devel file-devel \
        python3 python3-pip python3-devel \
        rust cargo \
        wget tar jq \
        2>&1 | tail -3 || {
            log "Some deps failed — trying minimal set..."
            dnf install -y gcc make libpcap-devel pcre2-devel libyaml-devel \
                zlib-devel jansson-devel python3 python3-pip wget tar jq 2>&1 | tail -3
        }

    # --- 4. Rust toolchain (Suricata 7+ needs rust for the parser crate) ---
    if ! command -v cargo >/dev/null 2>&1; then
        log "Installing Rust via rustup..."
        curl -sSf --proto "=https" --tlsv1.2 https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
        export PATH="$HOME/.cargo/bin:$PATH"
    fi

    # --- 5. suricata-update + PyYAML ---
    pip3 install --quiet pyyaml 2>&1 | tail -1 || true

    # --- 6. Download + extract source ---
    log "Downloading Suricata ${SURICATA_VER} source..."
    cd /tmp
    rm -rf suricata-build
    mkdir suricata-build && cd suricata-build
    wget -q "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VER}.tar.gz" -O suricata.tar.gz
    [ ! -s suricata.tar.gz ] && { log "ERROR: download failed"; exit 3; }
    tar xzf suricata.tar.gz
    cd "suricata-${SURICATA_VER}"

    # --- 7. Configure ---
    log "Running ./configure (this takes a minute)..."
    export PATH="$HOME/.cargo/bin:$PATH"
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --disable-gccmarch-native \
        2>&1 | tail -10

    # --- 8. Compile ---
    CPU_COUNT=$(nproc)
    log "Compiling with -j${CPU_COUNT} (this takes several minutes)..."
    make -j${CPU_COUNT} 2>&1 | tail -5

    # --- 9. Install ---
    log "Installing..."
    make install-full 2>&1 | tail -5
    ldconfig

    if ! command -v suricata >/dev/null 2>&1; then
        log "ERROR: suricata binary not found after install"
        exit 4
    fi
    log "Installed: $(suricata -V 2>&1 | head -1)"
fi

# --- 10. Create suricata system user if needed ---
if ! id suricata >/dev/null 2>&1; then
    log "Creating suricata system user..."
    useradd -r -s /sbin/nologin -d /var/lib/suricata suricata 2>/dev/null || true
fi

# --- 11. Ensure dirs exist ---
mkdir -p /var/log/suricata /var/lib/suricata/rules /etc/suricata /var/run/suricata
chown -R suricata:suricata /var/log/suricata /var/lib/suricata /var/run/suricata

# --- 12. Write systemd unit if missing ---
if [ ! -f /etc/systemd/system/suricata.service ] && [ ! -f /usr/lib/systemd/system/suricata.service ]; then
    log "Writing systemd unit..."
    cat > /etc/systemd/system/suricata.service <<UNIT
[Unit]
Description=Suricata IDS/IDP daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata/suricata.pid --af-packet -vvv
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
fi

# --- 13. Patch suricata.yaml ---
CONFIG=/etc/suricata/suricata.yaml
if [ ! -f "$CONFIG" ]; then
    log "ERROR: $CONFIG not found after install"
    exit 5
fi
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

# --- 14. Update sources + pull rules ---
log "Running suricata-update update-sources..."
suricata-update update-sources -q 2>&1 | tail -3 || true
log "Running suricata-update (downloading rules)..."
suricata-update -q 2>&1 | tail -3 || true

RULE_COUNT=$(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)
log "Rules loaded: $RULE_COUNT"

# --- 15. Validate ---
log "Validating config..."
suricata -T -c "$CONFIG" -i "$IFACE" 2>&1 | tail -5 || log "  (validation non-zero, may still work)"

# --- 16. Start ---
systemctl daemon-reload
systemctl enable suricata 2>&1 | tail -1
systemctl restart suricata
sleep 3

if systemctl is-active --quiet suricata; then
    log "✓ Suricata active"
else
    log "✗ Suricata failed — journalctl:"
    journalctl -u suricata -n 20 --no-pager
    exit 6
fi

# --- 17. Wazuh integration ---
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
        systemctl restart wazuh-agent
        sleep 2
    fi
fi

# --- 18. Verify ---
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
    log "  eve.json has $S1 bytes (idle — generate traffic to verify)"
else
    log "⚠ eve.json empty"
fi

log "DONE"
'

remediate_host() {
    local name="$1" ip="$2"
    echo ""
    echo -e "${B}${C}━━━ $name ${DIM}($ip)${RST}"

    if ! confirm "Build Suricata from source on $name? (will take ~10 min)"; then
        echo -e "  ${DIM}Skipped${RST}"
        return
    fi

    if ! ssh $SSH_OPTS "root@$ip" "echo ok" </dev/null >/dev/null 2>&1; then
        echo -e "  ${R}✗ SSH unreachable${RST}"
        return
    fi

    echo -e "  ${C}→ Starting source build (watch for progress)...${RST}"
    echo ""

    ssh $SSH_OPTS "root@$ip" "bash -s" <<< "$REMOTE_SCRIPT" 2>&1 | sed 's/^/    /'
    local rc=${PIPESTATUS[0]}

    echo ""
    if [ "$rc" -eq 0 ]; then
        echo -e "  ${G}${B}✓ Build + install complete for $name${RST}"
    else
        echo -e "  ${R}${B}✗ Exited with code $rc${RST}"
    fi
}

main() {
    banner

    echo -e "${Y}  Why source build?${RST}"
    echo -e "  ${DIM}- EPEL 10 does not ship Suricata anymore${RST}"
    echo -e "  ${DIM}- OSIF copr builds need DPDK 26 (not in RHEL 10 / Rocky 10)${RST}"
    echo -e "  ${DIM}- RHEL 10 Suricata requires active Red Hat subscription${RST}"
    echo -e "  ${DIM}- Source build sidesteps all of these${RST}"
    echo ""

    if ! confirm "Proceed with source-build remediation?"; then
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
