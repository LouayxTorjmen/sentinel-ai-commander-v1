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
#   1.  Check prerequisites (Docker, Docker Compose, Python 3, curl, openssl)
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

# ── Step 1: Prerequisites ─────────────────────────────────────────────────────
check_prerequisites() {
    step "Checking prerequisites"

    command -v docker   >/dev/null 2>&1 || fail "Docker not installed — https://docs.docker.com/engine/install/"
    ok "Docker $(docker --version | awk '{print $3}' | tr -d ,)"

    docker compose version >/dev/null 2>&1 \
        || fail "Docker Compose plugin missing — install 'docker-compose-plugin'"
    ok "Docker Compose $(docker compose version --short 2>/dev/null || docker compose version | awk '{print $NF}')"

    command -v python3 >/dev/null 2>&1 || fail "Python 3 required"
    ok "Python $(python3 --version | awk '{print $2}')"

    command -v curl    >/dev/null 2>&1 || fail "curl required"
    ok "curl"

    command -v openssl >/dev/null 2>&1 || fail "openssl required"
    ok "openssl"

    docker info >/dev/null 2>&1 \
        || fail "Docker daemon not running — start it with: sudo systemctl start docker"
    ok "Docker daemon running"
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

    check_prerequisites
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
