#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# SENTINEL-AI Commander — Setup Script
# ═══════════════════════════════════════════════════════════════════════
# Usage:
#   ./setup.sh                  Full setup (first-time deployment)
#   ./setup.sh --health-check   Check service health only
#   ./setup.sh --render-only    Regenerate Wazuh configs from .env only
#   ./setup.sh --inventory      Regenerate Ansible inventory only
#
# What this does:
#   1.  Install prerequisites — Docker, Docker Compose plugin, Python 3,
#       curl, openssl, git, envsubst, and all packages from requirements.txt.
#       Works on Debian/Ubuntu and RHEL/Fedora/CentOS. Skips if already installed.
#   2.  Create .env from .env.example with auto-generated secrets
#   3.  Prompt for required API keys (Cerebras, Groq, Gemini)
#   4.  Set SENTINEL_BASE_DIR to current working directory
#   5.  Generate SSH keypair for Ansible if missing
#   6.  Render Wazuh config files from templates + environment variables
#       (ossec.conf, local_rules.xml, certs.yml)
#   7.  Generate TLS certificates for Wazuh
#   8.  Start the full stack (Wazuh + AI agents + Ansible runner + Ollama)
#   9.  Pull Ollama model inside the container
#   10. Run health checks on all services
#   11. Generate Ansible inventory from the live Wazuh agent list
#   12. Print access URLs and next steps
#
# NOTE: Suricata is NOT started by this script. It runs on the network
#       gateway/firewall and must be configured separately on that device.
#       nmap is NOT required — agent enrollment uses Wazuh's built-in
#       auto-enrollment, not network scanning.
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"; B="\033[1m"; RST="\033[0m"

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT/.env"
ENV_EXAMPLE="$ROOT/.env.example"
SSH_KEY="$ROOT/ansible/keys/id_rsa"
CERT_DIR="$ROOT/wazuh/config/certs"

# ── Helpers ───────────────────────────────────────────────────────────────────
banner() {
    echo -e "${C}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║    🛡️   SENTINEL-AI Commander — Setup                      ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${RST}"
}

step()  { echo -e "\n${B}${C}[*] $1${RST}"; }
ok()    { echo -e "${G}  ✓ $1${RST}"; }
warn()  { echo -e "${Y}  ! $1${RST}"; }
fail()  { echo -e "${R}  ✗ $1${RST}"; exit 1; }
info()  { echo -e "    $1"; }

# Read a value from .env (works even if not sourced)
env_get() {
    grep -E "^${1}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'" | head -1
}


# ── Step 0: Platform detection and validation ─────────────────────────────────
check_platform() {
    step "Checking platform"
    local warnings=0
    IS_WSL=false; IS_CONTAINER=false; IS_LINUX=false

    if grep -qi microsoft /proc/version 2>/dev/null || \
       grep -qi wsl /proc/version 2>/dev/null; then
        IS_WSL=true
        ok "Platform: Windows Subsystem for Linux 2 (WSL2)"
    elif [ -f /.dockerenv ] || grep -q "docker\|containerd\|lxc" /proc/1/cgroup 2>/dev/null; then
        IS_CONTAINER=true
        warn "Platform: Running inside a container — Docker-in-Docker not officially supported"
    elif uname -s | grep -qi linux; then
        IS_LINUX=true
        ok "Platform: Linux ($(uname -r | cut -d- -f1))"
    else
        fail "Unsupported platform: $(uname -s). SENTINEL-AI requires Linux or WSL2."
    fi

    if [ "$IS_WSL" = true ]; then
        [ -f /proc/sys/fs/binfmt_misc/WSLInterop ] && ok "WSL2 kernel confirmed" || \
            warn "Could not confirm WSL2 — WSL1 is not supported"

        if echo "$ROOT" | grep -q "^/mnt/[a-z]/"; then
            echo ""
            echo -e "${R}${B}  CRITICAL: Repo is on the Windows filesystem (${ROOT})${RST}"
            echo -e "${R}  This causes Docker volume mount failures and severe I/O slowness.${RST}"
            echo -e "${R}  Move the repo to the WSL2 filesystem:${RST}"
            echo -e "  ${Y}cp -r ${ROOT} ~/sentinel-ai-commander${RST}"
            echo -e "  ${Y}cd ~/sentinel-ai-commander && ./setup.sh${RST}"
            echo ""
            fail "Move repo to WSL2 filesystem and re-run setup.sh"
        fi
        ok "Repo location: ${ROOT}"

        local mem_kb mem_gb
        mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        mem_gb=$(( mem_kb / 1024 / 1024 ))
        if [ "$mem_gb" -lt 6 ]; then
            warn "WSL2 has only ${mem_gb}GB RAM — Wazuh needs at least 6GB"
            warn "Add to C:\\Users\\YourName\\.wslconfig:"
            info "  [wsl2]"
            info "  memory=12GB"
            info "  processors=4"
            info "Then: wsl --shutdown  (from PowerShell), then reopen terminal"
            warnings=$((warnings + 1))
        else
            ok "WSL2 memory: ${mem_gb}GB"
        fi
    fi

    local mem_kb mem_gb
    mem_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
    mem_gb=$(( mem_kb / 1024 / 1024 ))
    if [ "$mem_gb" -lt 6 ]; then
        warn "${mem_gb}GB RAM — minimum 8GB recommended (Wazuh indexer needs 4GB alone)"
        warnings=$((warnings + 1))
    elif [ "$mem_gb" -lt 10 ]; then
        warn "RAM: ${mem_gb}GB — 16GB recommended for stable production use"
    else
        ok "RAM: ${mem_gb}GB"
    fi

    local free_gb
    free_gb=$(df -BG "$ROOT" 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G' || echo 0)
    if [ "$free_gb" -lt 20 ]; then
        warn "Only ${free_gb}GB free disk — minimum 50GB recommended"
        warnings=$((warnings + 1))
    else
        ok "Disk: ${free_gb}GB free"
    fi

    curl -s --max-time 5 https://hub.docker.com >/dev/null 2>&1 \
        && ok "Internet: Docker Hub reachable" \
        || { warn "Cannot reach Docker Hub — image pulls will fail"; warnings=$((warnings + 1)); }

    if [ "$(id -u)" = "0" ]; then
        ok "Running as root"
    elif sudo -n true 2>/dev/null; then
        ok "sudo access confirmed"
    else
        warn "Not root and sudo requires a password — some steps may prompt for it"
    fi

    case "$(uname -m)" in
        x86_64|amd64)  ok  "Architecture: x86_64" ;;
        aarch64|arm64) warn "Architecture: ARM64 — Wazuh may be unstable on ARM"
                       warnings=$((warnings + 1)) ;;
        *)             fail "Unsupported CPU architecture: $(uname -m)" ;;
    esac

    echo ""
    if [ $warnings -gt 0 ]; then
        warn "$warnings warning(s) above — review before continuing"
        echo ""
        read -rp "  Continue anyway? [y/N] " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || fail "Setup aborted by user"
    else
        ok "Platform checks passed"
    fi
}

# ── Step 1: Detect OS ─────────────────────────────────────────────────────────
detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_FAMILY="${ID_LIKE:-$ID}"
    elif command -v uname >/dev/null 2>&1; then
        OS_ID="$(uname -s | tr '[:upper:]' '[:lower:]')"
        OS_FAMILY="$OS_ID"
    else
        OS_ID="unknown"
        OS_FAMILY="unknown"
    fi
}

# ── Step 1: Install prerequisites ─────────────────────────────────────────────
install_prerequisites() {
    step "Installing prerequisites"
    detect_os

    # ── System packages ───────────────────────────────────────────────────────
    if echo "$OS_FAMILY" in *"debian"* *"ubuntu"* 2>/dev/null || \
       [[ "$OS_ID" =~ ^(debian|ubuntu|linuxmint|pop|elementary)$ ]]; then

        info "Detected Debian/Ubuntu — using apt"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq

        # Docker
        if ! command -v docker >/dev/null 2>&1; then
            info "Installing Docker..."
            apt-get install -y -qq ca-certificates curl gnupg lsb-release
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
                | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null || true
            # Fall back to distro package if key fails (works on most Ubuntu versions)
            apt-get install -y -qq docker.io docker-compose-plugin 2>/dev/null || \
            apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
        fi

        # Core tools
        apt-get install -y -qq \
            python3 python3-pip python3-venv \
            curl openssl git openssh-client \
            gettext-base 2>/dev/null || true

    elif [[ "$OS_FAMILY" =~ rhel|fedora|centos|almalinux|rocky ]]; then

        info "Detected RHEL/Fedora family — using dnf/yum"
        local pkg_mgr="dnf"
        command -v dnf >/dev/null 2>&1 || pkg_mgr="yum"

        # Docker
        if ! command -v docker >/dev/null 2>&1; then
            info "Installing Docker..."
            $pkg_mgr install -y -q yum-utils 2>/dev/null || true
            yum-config-manager --add-repo \
                https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null || true
            $pkg_mgr install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin
        fi

        # Core tools
        $pkg_mgr install -y -q \
            python3 python3-pip \
            curl openssl git openssh-clients \
            gettext 2>/dev/null || true

    else
        warn "Unrecognised OS: $OS_ID — skipping system package installation"
        warn "Ensure these are installed manually: docker, docker-compose-plugin,"
        warn "  python3, python3-pip, curl, openssl, git, gettext"
    fi

    # ── Docker service ────────────────────────────────────────────────────────
    if ! docker info >/dev/null 2>&1; then
        info "Starting Docker daemon..."
        systemctl start docker  2>/dev/null || \
        service docker start    2>/dev/null || \
        dockerd &>/tmp/dockerd.log &
        sleep 5
    fi

    if docker info >/dev/null 2>&1; then
        ok "Docker $(docker --version | awk '{print $3}' | tr -d ,)"
    else
        fail "Docker daemon not responding. Start manually: sudo systemctl start docker"
    fi

    # ── Docker Compose plugin check ───────────────────────────────────────────
    if ! docker compose version >/dev/null 2>&1; then
        # Try installing the standalone compose plugin
        info "Installing Docker Compose plugin..."
        COMPOSE_VER=$(curl -s https://api.github.com/repos/docker/compose/releases/latest \
            | grep '"tag_name"' | cut -d'"' -f4 || echo "v2.24.0")
        ARCH=$(uname -m)
        mkdir -p /usr/local/lib/docker/cli-plugins
        curl -fsSL \
            "https://github.com/docker/compose/releases/download/${COMPOSE_VER}/docker-compose-linux-${ARCH}" \
            -o /usr/local/lib/docker/cli-plugins/docker-compose
        chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
    fi
    docker compose version >/dev/null 2>&1 \
        || fail "Docker Compose plugin still missing after install attempt"
    ok "Docker Compose $(docker compose version --short 2>/dev/null || echo 'installed')"

    # ── Python ────────────────────────────────────────────────────────────────
    command -v python3 >/dev/null 2>&1 \
        || fail "Python 3 not installed and could not be installed automatically"
    ok "Python $(python3 --version | awk '{print $2}')"

    # ── Python packages from requirements.txt ────────────────────────────────
    local req_file="$ROOT/requirements.txt"
    if [ -f "$req_file" ]; then
        info "Installing Python packages from requirements.txt..."
        # Try without --break-system-packages first, then with it (needed on newer Debian/Ubuntu)
        pip3 install -q -r "$req_file" 2>/dev/null || \
        pip3 install -q -r "$req_file" --break-system-packages 2>/dev/null || \
        python3 -m pip install -q -r "$req_file" --break-system-packages || {
            warn "pip install failed — trying with a virtual environment"
            python3 -m venv "$ROOT/.venv"
            "$ROOT/.venv/bin/pip" install -q -r "$req_file"
            warn "Packages installed in .venv — activate with: source .venv/bin/activate"
        }
        ok "Python packages installed"
    else
        warn "requirements.txt not found — skipping Python package installation"
    fi

    # ── Other tools ───────────────────────────────────────────────────────────
    command -v curl    >/dev/null 2>&1 && ok "curl"    || warn "curl missing — install manually"
    command -v openssl >/dev/null 2>&1 && ok "openssl" || warn "openssl missing — install manually"
    command -v git     >/dev/null 2>&1 && ok "git"     || warn "git missing — install manually"

    # gettext provides envsubst (used for template rendering)
    command -v envsubst >/dev/null 2>&1 && ok "envsubst" || {
        warn "envsubst not found — template rendering may fail"
        warn "Install: apt install gettext-base (Debian) or dnf install gettext (RHEL)"
    }

    # Add current user to docker group if not root (avoids sudo for every docker command)
    if [ "$(id -u)" != "0" ] && ! groups | grep -q docker; then
        warn "Adding $(whoami) to docker group — you may need to log out and back in"
        usermod -aG docker "$(whoami)" 2>/dev/null || true
    fi
}

# ── Step 2: .env file ─────────────────────────────────────────────────────────
setup_env() {
    step "Setting up .env"

    if [ -f "$ENV_FILE" ]; then
        ok ".env already exists — keeping existing values"
    else
        [ -f "$ENV_EXAMPLE" ] || fail ".env.example not found — is this the correct directory?"
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        ok "Created .env from .env.example"

        # Auto-generate random secrets
        info "Generating random passwords..."
        gen_pw() { openssl rand -base64 32 | tr -d '=+/\n' | head -c 28; }

        local wazuh_api_pw wazuh_idx_pw wazuh_dash_pw postgres_pw redis_pw cluster_key
        wazuh_api_pw=$(gen_pw)
        wazuh_idx_pw=$(gen_pw)
        wazuh_dash_pw=$(gen_pw)
        postgres_pw=$(gen_pw)
        redis_pw=$(gen_pw)
        cluster_key=$(openssl rand -base64 32 | tr -d '\n')

        sed -i "s|WAZUH_API_PASSWORD=.*|WAZUH_API_PASSWORD=${wazuh_api_pw}|"       "$ENV_FILE"
        sed -i "s|WAZUH_INDEXER_PASSWORD=.*|WAZUH_INDEXER_PASSWORD=${wazuh_idx_pw}|" "$ENV_FILE"
        sed -i "s|WAZUH_DASHBOARD_PASSWORD=.*|WAZUH_DASHBOARD_PASSWORD=${wazuh_dash_pw}|" "$ENV_FILE"
        sed -i "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${postgres_pw}|"           "$ENV_FILE"
        sed -i "s|REDIS_PASSWORD=.*|REDIS_PASSWORD=${redis_pw}|"                   "$ENV_FILE"
        sed -i "s|WAZUH_CLUSTER_KEY=.*|WAZUH_CLUSTER_KEY=${cluster_key}|"         "$ENV_FILE"
        ok "Generated random passwords for Wazuh, Postgres, Redis"

        # Auto-detect host LAN IP
        local host_ip
        host_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' | head -1 || echo "")
        if [ -n "$host_ip" ]; then
            sed -i "s|WAZUH_MANAGER_EXTERNAL_IP=.*|WAZUH_MANAGER_EXTERNAL_IP=${host_ip}|" "$ENV_FILE"
            ok "Detected host LAN IP: ${host_ip}"
        else
            warn "Could not auto-detect host IP — set WAZUH_MANAGER_EXTERNAL_IP in .env manually"
        fi
    fi

    # Always set SENTINEL_BASE_DIR to this directory (portable regardless of where the repo is cloned)
    if grep -q "^SENTINEL_BASE_DIR=" "$ENV_FILE"; then
        sed -i "s|SENTINEL_BASE_DIR=.*|SENTINEL_BASE_DIR=${ROOT}|" "$ENV_FILE"
    else
        echo "SENTINEL_BASE_DIR=${ROOT}" >> "$ENV_FILE"
    fi
    ok "SENTINEL_BASE_DIR set to: ${ROOT}"

    # Prompt for LLM API keys if not already set
    local cerebras groq gemini
    cerebras=$(env_get "CEREBRAS_API_KEY")
    groq=$(env_get "GROQ_API_KEY")
    gemini=$(env_get "GEMINI_API_KEY")

    if [ -z "$cerebras" ] && [ -z "$groq" ] && [ -z "$gemini" ]; then
        echo ""
        warn "No LLM API keys found. At least one is required for AI features."
        warn "Add your keys to .env now:"
        info "  CEREBRAS_API_KEY  — https://cloud.cerebras.ai"
        info "  GROQ_API_KEY      — https://console.groq.com/keys"
        info "  GEMINI_API_KEY    — https://aistudio.google.com/app/apikey"
        echo ""
        read -rp "  Press Enter once you have added at least one API key to .env, or Ctrl+C to abort... " _
    else
        [ -n "$cerebras" ] && ok "CEREBRAS_API_KEY present"
        [ -n "$groq" ]     && ok "GROQ_API_KEY present"
        [ -n "$gemini" ]   && ok "GEMINI_API_KEY present"
    fi
}

# ── Step 3: SSH keypair ───────────────────────────────────────────────────────
setup_ssh_keys() {
    step "Setting up SSH keypair for Ansible"
    mkdir -p "$(dirname "$SSH_KEY")"

    if [ -f "$SSH_KEY" ]; then
        ok "SSH key already exists at $SSH_KEY"
        return
    fi

    ssh-keygen -t rsa -b 4096 -f "$SSH_KEY" -N "" -C "sentinel-ai@$(hostname)" >/dev/null
    chmod 600 "$SSH_KEY"
    chmod 644 "$SSH_KEY.pub"
    ok "Generated new SSH keypair"
    warn "Public key — deploy this to your Linux agents via authorized_keys:"
    cat "$SSH_KEY.pub" | sed 's/^/    /'
    echo ""
    warn "For Windows agents, WinRM authentication is used instead (no SSH key needed)."
}

# ── Step 4: Render Wazuh configs from templates ───────────────────────────────
render_wazuh_configs() {
    step "Rendering Wazuh configuration from templates"

    local render_script="$ROOT/scripts/render_wazuh_config.py"
    [ -f "$render_script" ] || fail "scripts/render_wazuh_config.py not found"

    # Source .env so the render script picks up all values
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a

    # Validate first
    python3 "$render_script" --check || fail "Wazuh config validation failed — check .env values"

    # Render
    python3 "$render_script"
    ok "Wazuh configs rendered from environment variables"
    warn "If you change subnet values in .env, run: python3 scripts/render_wazuh_config.py"
}

# ── Step 5: TLS certificates ──────────────────────────────────────────────────
setup_tls_certs() {
    step "Setting up TLS certificates for Wazuh"

    if [ -f "$CERT_DIR/wazuh.manager.pem" ]; then
        ok "TLS certificates already present"
        return
    fi

    mkdir -p "$CERT_DIR"

    local gen_script="$ROOT/scripts/gen_certs.sh"
    if [ -f "$gen_script" ]; then
        bash "$gen_script"
        ok "TLS certificates generated"
    else
        warn "scripts/gen_certs.sh not found — Wazuh may fail to start without certificates"
        warn "Generate certificates manually and place them in: $CERT_DIR"
    fi
}

# ── Step 6: Render template configs (filebeat, dashboard, indexer users) ──────
render_service_templates() {
    step "Rendering service configuration templates"

    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a

    # Generate bcrypt hashes for Wazuh indexer users (required for internal_users.yml)
    if [ -f "$ROOT/wazuh/config/indexer/internal_users.yml.template" ]; then
        info "Generating bcrypt hashes for Wazuh indexer users..."

        local hash_admin hash_kibana
        hash_admin=$(python3 -c "
import bcrypt, os
pw = os.environ.get('WAZUH_INDEXER_PASSWORD', '').encode()
if not pw: raise ValueError('WAZUH_INDEXER_PASSWORD not set')
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode())
" 2>/dev/null) || {
            warn "Python bcrypt not installed — using Docker for hash generation"
            local wazuh_ver
            wazuh_ver=$(env_get "WAZUH_VERSION" || echo "4.14.4")
            hash_admin=$(docker run --rm "wazuh/wazuh-indexer:${wazuh_ver}" \
                bash -c "echo '${WAZUH_INDEXER_PASSWORD}' | \
                /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh 2>/dev/null | tail -1")
        }

        hash_kibana=$(python3 -c "
import bcrypt, os
pw = os.environ.get('WAZUH_DASHBOARD_PASSWORD', '').encode()
if not pw: raise ValueError('WAZUH_DASHBOARD_PASSWORD not set')
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode())
" 2>/dev/null) || {
            local wazuh_ver
            wazuh_ver=$(env_get "WAZUH_VERSION" || echo "4.14.4")
            hash_kibana=$(docker run --rm "wazuh/wazuh-indexer:${wazuh_ver}" \
                bash -c "echo '${WAZUH_DASHBOARD_PASSWORD}' | \
                /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh 2>/dev/null | tail -1")
        }

        export WAZUH_INDEXER_HASH_ADMIN="$hash_admin"
        export WAZUH_INDEXER_HASH_KIBANA="$hash_kibana"
        ok "Bcrypt hashes generated"
    fi

    # Render all .template files that have a corresponding envsubst pattern
    local templates=(
        "wazuh/config/filebeat.yml.template"
        "wazuh/config/dashboard/opensearch_dashboards.yml.template"
        "wazuh/config/dashboard/wazuh.yml.template"
        "wazuh/config/indexer/internal_users.yml.template"
    )

    for tpl in "${templates[@]}"; do
        if [ -f "$ROOT/$tpl" ]; then
            local out="${ROOT}/${tpl%.template}"
            envsubst < "$ROOT/$tpl" > "$out"
            ok "Rendered $(basename "$out")"
        fi
    done
}

# ── Step 7: Start the stack ───────────────────────────────────────────────────
start_stack() {
    step "Starting Docker Compose stack"
    cd "$ROOT"

    info "Building images..."
    docker compose build --quiet 2>&1 | tail -3

    echo ""
    info "Starting Wazuh stack (indexer, manager, dashboard)..."
    cd "$ROOT/wazuh"
    docker compose up -d
    cd "$ROOT"

    info "Waiting for Wazuh indexer to initialize (90s)..."
    info "This is normal — the OpenSearch indexer takes time to start on first boot."
    sleep 90

    info "Starting AI agents, Ansible runner, Postgres, Redis, Nginx, Ollama..."
    docker compose up -d

    sleep 15
    ok "Stack started"
    warn "NOTE: Suricata is not started by this script."
    warn "      Deploy Suricata on your network gateway/firewall separately."
}

# ── Step 8: Pull Ollama model ─────────────────────────────────────────────────
pull_ollama_model() {
    step "Pulling Ollama fallback model"
    local model
    model=$(env_get "OLLAMA_MODEL" || echo "llama3.2:3b")

    if docker ps --format '{{.Names}}' | grep -q "sentinel-ollama"; then
        info "Starting background pull for model: $model"
        docker exec sentinel-ollama ollama pull "$model" &
        ok "Ollama pull running in background"
        ok "Monitor with: docker exec sentinel-ollama ollama list"
    else
        warn "Ollama container not running — model will be pulled on first use"
    fi
}

# ── Step 9: Generate Ansible inventory ────────────────────────────────────────
generate_inventory() {
    step "Generating Ansible inventory from Wazuh agent list"

    local inventory_script="$ROOT/ansible/dynamic_inventory.py"
    local inventory_file="$ROOT/ansible/inventory/hosts.ini"

    if [ ! -f "$inventory_script" ]; then
        warn "ansible/dynamic_inventory.py not found — skipping inventory generation"
        return
    fi

    # Wait a moment for Wazuh manager to be reachable
    local retries=5
    local wazuh_api_port
    wazuh_api_port=$(env_get "PORT_WAZUH_API" || echo "50001")

    info "Waiting for Wazuh API (up to 60s)..."
    for i in $(seq 1 $retries); do
        if curl -sk "https://localhost:${wazuh_api_port}/" >/dev/null 2>&1; then
            break
        fi
        sleep 12
        [ "$i" -eq "$retries" ] && {
            warn "Wazuh API not reachable — inventory generation skipped"
            warn "Run manually once Wazuh is ready: python3 ansible/dynamic_inventory.py"
            return
        }
    done

    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a

    python3 "$inventory_script" > "$inventory_file" 2>/dev/null && {
        ok "Inventory written to: ansible/inventory/hosts.ini"
        local agent_count
        agent_count=$(grep -c "ansible_host=" "$inventory_file" 2>/dev/null || echo 0)
        ok "Agents found: $agent_count"
    } || {
        warn "Inventory generation failed — Wazuh may have no agents enrolled yet"
        warn "Run after enrolling agents: python3 ansible/dynamic_inventory.py"
    }
}

# ── Step 10: Health checks ────────────────────────────────────────────────────
check_health() {
    step "Checking service health"
    local failures=0

    svc_check() {
        local name=$1
        shift
        if eval "$@" >/dev/null 2>&1; then
            ok "$name"
        else
            warn "$name not responding (may still be starting)"
            failures=$((failures + 1))
        fi
    }

    local wazuh_api_port wazuh_idx_port ai_port ansible_port
    wazuh_api_port=$(env_get "PORT_WAZUH_API"       || echo "50001")
    wazuh_idx_port=$(env_get "PORT_WAZUH_INDEXER"   || echo "50002")
    ai_port=$(env_get "PORT_AI_AGENTS"              || echo "50010")
    ansible_port=$(env_get "PORT_ANSIBLE_RUNNER"    || echo "50011")

    local idx_pw
    idx_pw=$(env_get "WAZUH_INDEXER_PASSWORD" || echo "")

    svc_check "Wazuh Indexer"     "curl -sk --max-time 5 https://localhost:${wazuh_idx_port}/_cluster/health -u admin:${idx_pw}"
    svc_check "Wazuh Manager API" "curl -sk --max-time 5 https://localhost:${wazuh_api_port}/"
    svc_check "AI Agents"         "curl -s  --max-time 5 http://localhost:${ai_port}/health"
    svc_check "Ansible Runner"    "curl -s  --max-time 5 http://localhost:${ansible_port}/health"

    if docker ps --format '{{.Names}}' | grep -q "sentinel-postgres"; then
        ok "PostgreSQL (container running)"
    else
        warn "PostgreSQL container not found"; failures=$((failures + 1))
    fi

    if docker ps --format '{{.Names}}' | grep -q "sentinel-redis"; then
        ok "Redis (container running)"
    else
        warn "Redis container not found"; failures=$((failures + 1))
    fi

    echo ""
    if [ $failures -eq 0 ]; then
        ok "All services healthy"
    else
        warn "$failures service(s) not yet responding"
        warn "Services may still be initializing. Re-check with: ./setup.sh --health-check"
    fi
}

# ── Step 11: Print next steps ─────────────────────────────────────────────────
print_next_steps() {
    local host_ip
    host_ip=$(env_get "WAZUH_MANAGER_EXTERNAL_IP" || hostname -I | awk '{print $1}')

    local nginx_https_port dash_port ai_port
    nginx_https_port=$(env_get "NGINX_HTTPS_PORT"    || echo "50021")
    dash_port=$(env_get "PORT_WAZUH_DASHBOARD"       || echo "50000")
    ai_port=$(env_get "PORT_AI_AGENTS"               || echo "50010")

    local idx_user idx_pw
    idx_user=$(env_get "WAZUH_INDEXER_USER"          || echo "admin")

    echo ""
    echo -e "${G}${B}═══════════════════════════════════════════════════════════${RST}"
    echo -e "${G}${B}  ✅  SENTINEL-AI Commander is running${RST}"
    echo -e "${G}${B}═══════════════════════════════════════════════════════════${RST}"
    echo ""
    echo -e "${B}Access URLs:${RST}"
    echo -e "  Chat Interface:    ${C}https://${host_ip}:${nginx_https_port}/${RST}"
    echo -e "  Wazuh Dashboard:   ${C}https://${host_ip}:${dash_port}/${RST}"
    echo -e "  AI Agents API:     ${C}http://localhost:${ai_port}/docs${RST}"
    echo ""
    echo -e "${B}Wazuh credentials:${RST}  user=${idx_user}  password=see .env"
    echo ""
    echo -e "${B}Next steps:${RST}"
    echo ""
    echo -e "  ${C}1.${RST} Enroll your agents (Linux + Windows hosts):"
    echo -e "     ${Y}python3 enroll.py${RST}"
    echo ""
    echo -e "  ${C}2.${RST} Regenerate Ansible inventory after enrollment:"
    echo -e "     ${Y}python3 ansible/dynamic_inventory.py > ansible/inventory/hosts.ini${RST}"
    echo ""
    echo -e "  ${C}3.${RST} If you change subnet values in .env, re-render Wazuh configs:"
    echo -e "     ${Y}python3 scripts/render_wazuh_config.py${RST}"
    echo -e "     ${Y}bash scripts/gen_certs.sh   # if Docker internal IPs changed${RST}"
    echo ""
    echo -e "  ${C}4.${RST} Suricata must be installed separately on your gateway/firewall."
    echo -e "     It is NOT managed by this setup script."
    echo ""
    echo -e "  ${C}5.${RST} Monitor logs:"
    echo -e "     ${Y}docker compose logs -f sentinel-ai-agents${RST}"
    echo ""
    echo -e "${B}Credentials are in .env — never commit that file.${RST}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    banner

    case "${1:-}" in
        --health-check)
            check_health
            exit 0
            ;;
        --render-only)
            step "Re-rendering Wazuh configs from .env"
            render_wazuh_configs
            ok "Done. Restart the Wazuh stack for changes to take effect:"
            info "  cd wazuh && docker compose restart"
            exit 0
            ;;
        --inventory)
            generate_inventory
            exit 0
            ;;
    esac

    check_platform
    install_prerequisites
    setup_env
    setup_ssh_keys
    render_wazuh_configs
    setup_tls_certs
    render_service_templates
    start_stack
    pull_ollama_model
    sleep 20
    check_health
    generate_inventory
    print_next_steps
}

main "$@"
