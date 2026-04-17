#!/usr/bin/env bash
# =============================================================================
#  scripts/preflight.sh — Host detection, prerequisite validation, sysctl tuning
#  Compatible with: WSL2, VM (VirtualBox/VMware/KVM), bare metal Linux
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
fatal() { fail "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ─── Load .env if present ────────────────────────────────────────────────────
if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a; source "$PROJECT_ROOT/.env"; set +a
fi
DEPLOY_MODE="${DEPLOY_MODE:-auto}"

echo ""
echo "============================================="
echo "  SENTINEL-AI COMMANDER — Preflight Check"
echo "============================================="
echo ""

# ─── 1. Detect environment ───────────────────────────────────────────────────
detect_environment() {
    if [ "$DEPLOY_MODE" != "auto" ]; then
        info "Deploy mode forced: $DEPLOY_MODE"
        echo "$DEPLOY_MODE"
        return
    fi

    # WSL2 detection
    if grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
        echo "wsl2"
        return
    fi

    # VM detection
    if command -v systemd-detect-virt &>/dev/null; then
        local virt
        virt=$(systemd-detect-virt 2>/dev/null || echo "none")
        if [ "$virt" != "none" ]; then
            echo "vm"
            return
        fi
    fi

    # Check DMI for VM signatures
    if [ -f /sys/class/dmi/id/product_name ]; then
        local product
        product=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "")
        case "$product" in
            *VirtualBox*|*VMware*|*QEMU*|*KVM*|*Hyper-V*)
                echo "vm"
                return
                ;;
        esac
    fi

    echo "baremetal"
}

ENV_TYPE=$(detect_environment)
ok "Environment detected: $ENV_TYPE"

# ─── 2. Check required tools ─────────────────────────────────────────────────
info "Checking prerequisites..."
MISSING=()

for cmd in docker curl openssl; do
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd $(${cmd} --version 2>&1 | head -1 | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo 'found')"
    else
        MISSING+=("$cmd")
        fail "$cmd not found"
    fi
done

# Check Docker Compose (v2 plugin)
if docker compose version &>/dev/null; then
    ok "docker compose $(docker compose version --short 2>/dev/null || echo 'found')"
else
    MISSING+=("docker-compose-v2")
    fail "docker compose v2 not found (install: apt install docker-compose-plugin)"
fi

# Check Docker daemon is running
if docker info &>/dev/null; then
    ok "Docker daemon running"
else
    fatal "Docker daemon not running. Start it: sudo systemctl start docker"
fi

# Check user can run Docker
if docker ps &>/dev/null; then
    ok "Docker permissions OK"
else
    fatal "Cannot run Docker. Add user to docker group: sudo usermod -aG docker \$USER"
fi

if [ ${#MISSING[@]} -gt 0 ]; then
    fatal "Missing tools: ${MISSING[*]}. Install them and re-run."
fi

# ─── 3. Sysctl tuning (Wazuh OpenSearch requires these) ─────────────────────
info "Configuring kernel parameters..."

configure_sysctl() {
    local key="$1" value="$2"
    local current
    current=$(sysctl -n "$key" 2>/dev/null || echo "0")

    if [ "$current" -ge "$value" ] 2>/dev/null; then
        ok "$key = $current (>= $value)"
        return
    fi

    warn "$key = $current (need >= $value), setting..."
    if sudo sysctl -w "$key=$value" &>/dev/null; then
        ok "$key set to $value"
    else
        fail "Could not set $key. Run: sudo sysctl -w $key=$value"
        return 1
    fi

    # Persist across reboots (not effective in WSL2 without /etc/wsl.conf trick)
    if [ "$ENV_TYPE" != "wsl2" ]; then
        if ! grep -q "^$key" /etc/sysctl.conf 2>/dev/null; then
            echo "$key = $value" | sudo tee -a /etc/sysctl.conf >/dev/null
            ok "$key persisted in /etc/sysctl.conf"
        fi
    fi
}

configure_sysctl "vm.max_map_count" 262144
configure_sysctl "net.core.somaxconn" 65535

# WSL2-specific: remind user about .wslconfig
if [ "$ENV_TYPE" = "wsl2" ]; then
    warn "WSL2 detected: vm.max_map_count resets on WSL restart."
    warn "To persist, create/edit %UserProfile%\\.wslconfig on Windows:"
    echo "    [wsl2]"
    echo "    kernelCommandLine = sysctl.vm.max_map_count=262144"
    echo ""
fi

# ─── 4. Check available RAM ──────────────────────────────────────────────────
info "Checking resources..."
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_MEM_GB=$((TOTAL_MEM_KB / 1024 / 1024))

if [ "$TOTAL_MEM_GB" -ge 8 ]; then
    ok "RAM: ${TOTAL_MEM_GB} GB (>= 8 GB)"
elif [ "$TOTAL_MEM_GB" -ge 6 ]; then
    warn "RAM: ${TOTAL_MEM_GB} GB (8 GB recommended, may work with reduced heap)"
else
    fatal "RAM: ${TOTAL_MEM_GB} GB (minimum 6 GB required, 8+ recommended)"
fi

# Check disk space (need at least 10 GB free)
FREE_DISK_KB=$(df "$PROJECT_ROOT" | tail -1 | awk '{print $4}')
FREE_DISK_GB=$((FREE_DISK_KB / 1024 / 1024))
if [ "$FREE_DISK_GB" -ge 10 ]; then
    ok "Disk: ${FREE_DISK_GB} GB free (>= 10 GB)"
else
    warn "Disk: ${FREE_DISK_GB} GB free (10+ GB recommended)"
fi

# ─── 5. Detect network interface for Suricata ────────────────────────────────
info "Detecting network interface..."
if [ -n "${SURICATA_INTERFACE:-}" ]; then
    ok "Suricata interface: $SURICATA_INTERFACE (from .env)"
else
    # Find the default route interface
    DEFAULT_IF=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)
    if [ -n "$DEFAULT_IF" ]; then
        ok "Default interface: $DEFAULT_IF (will be used for Suricata)"
        # Write to .env if not already set
        if [ -f "$PROJECT_ROOT/.env" ] && ! grep -q "^SURICATA_INTERFACE=" "$PROJECT_ROOT/.env"; then
            echo "SURICATA_INTERFACE=$DEFAULT_IF" >> "$PROJECT_ROOT/.env"
        fi
    else
        warn "Could not detect default network interface. Set SURICATA_INTERFACE in .env"
    fi
fi

# ─── 6. Detect LAN IP for Wazuh agent connectivity ──────────────────────────
info "Detecting host IP for remote Wazuh agent connectivity..."
if [ "$ENV_TYPE" = "wsl2" ]; then
    # WSL2: get the eth0 IP (visible from Windows host, may need port forwarding for LAN)
    HOST_IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    if [ -n "$HOST_IP" ]; then
        ok "WSL2 IP: $HOST_IP"
        warn "For LAN agents: configure Windows port forwarding from Windows IP to $HOST_IP"
        warn "  netsh interface portproxy add v4tov4 listenport=50042 listenaddress=0.0.0.0 connectport=50042 connectaddress=$HOST_IP"
        warn "  netsh interface portproxy add v4tov4 listenport=50041 listenaddress=0.0.0.0 connectport=50041 connectaddress=$HOST_IP"
    fi
else
    HOST_IP=$(ip -4 addr show "$DEFAULT_IF" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || hostname -I | awk '{print $1}')
    if [ -n "$HOST_IP" ]; then
        ok "Host IP: $HOST_IP (Wazuh agents should connect to this)"
    fi
fi

# ─── 7. Check .env completeness ─────────────────────────────────────────────
info "Checking .env configuration..."
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    warn ".env not found — will be created by setup.sh"
else
    UNSET=()
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        key=$(echo "$line" | cut -d= -f1)
        val=$(echo "$line" | cut -d= -f2-)
        if [[ "$val" == "CHANGE_ME"* ]]; then
            UNSET+=("$key")
        fi
    done < "$PROJECT_ROOT/.env"

    if [ ${#UNSET[@]} -gt 0 ]; then
        warn "These .env variables still have placeholder values:"
        for v in "${UNSET[@]}"; do
            echo "    $v"
        done
    else
        ok ".env fully configured"
    fi
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo "  Preflight Summary"
echo "============================================="
echo "  Environment:  $ENV_TYPE"
echo "  RAM:          ${TOTAL_MEM_GB} GB"
echo "  Disk free:    ${FREE_DISK_GB} GB"
echo "  Host IP:      ${HOST_IP:-unknown}"
echo "  Interface:    ${DEFAULT_IF:-unknown}"
echo "============================================="
echo ""
ok "Preflight checks passed. Ready for Phase 1."
