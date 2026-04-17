#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# SENTINEL-AI Commander v1 — Setup Script
# ═══════════════════════════════════════════════════════════════════════
# Usage: ./setup.sh
#
# What this does:
#   1. Checks prerequisites (Docker, Docker Compose, Python, curl)
#   2. Generates .env from .env.example if missing
#   3. Generates SSH keypair for Ansible if missing
#   4. Generates TLS certs for Wazuh if missing
#   5. Auto-detects host LAN IP for WAZUH_MANAGER_EXTERNAL_IP
#   6. Pulls Ollama model
#   7. Starts the full stack
#   8. Waits for health checks
#   9. Prints the access URLs and next steps
# ═══════════════════════════════════════════════════════════════════════
set -e

# Colors
G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"; B="\033[1m"; RST="\033[0m"

# Paths
ROOT="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$ROOT/.env"
ENV_EXAMPLE="$ROOT/.env.example"
SSH_KEY="$ROOT/ansible/keys/id_rsa"
CERT_DIR="$ROOT/wazuh/config/certs"

banner() {
    echo -e "${C}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║    🛡️   SENTINEL-AI Commander v1 — Setup                   ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${RST}"
}

step()    { echo -e "\n${B}${C}[*] $1${RST}"; }
ok()      { echo -e "${G}  ✓ $1${RST}"; }
warn()    { echo -e "${Y}  ! $1${RST}"; }
fail()    { echo -e "${R}  ✗ $1${RST}"; exit 1; }

# ─── Step 1: Prerequisites ───────────────────────────────────────────────
check_prerequisites() {
    step "Checking prerequisites"

    command -v docker >/dev/null 2>&1 || fail "Docker not installed — https://docs.docker.com/engine/install/"
    ok "Docker $(docker --version | awk '{print $3}' | tr -d ,)"

    if ! docker compose version >/dev/null 2>&1; then
        fail "Docker Compose plugin missing — install 'docker-compose-plugin'"
    fi
    ok "Docker Compose $(docker compose version --short)"

    command -v python3 >/dev/null 2>&1 || fail "Python 3 required"
    ok "Python $(python3 --version | awk '{print $2}')"

    command -v curl >/dev/null 2>&1 || fail "curl required"
    ok "curl"

    command -v openssl >/dev/null 2>&1 || fail "openssl required"
    ok "openssl"

    if ! command -v nmap >/dev/null 2>&1; then
        warn "nmap not installed — needed for enrollment network scan"
        warn "Install: apt install nmap / dnf install nmap"
    else
        ok "nmap $(nmap --version | head -1 | awk '{print $3}')"
    fi

    if ! docker info >/dev/null 2>&1; then
        fail "Docker daemon not running. Start it with: sudo systemctl start docker"
    fi
    ok "Docker daemon running"
}

# ─── Step 2: .env file ───────────────────────────────────────────────────
setup_env() {
    step "Setting up .env"
    if [ -f "$ENV_FILE" ]; then
        ok ".env already exists — keeping it"
        return
    fi

    [ ! -f "$ENV_EXAMPLE" ] && fail ".env.example missing"
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    ok "Created .env from .env.example"

    # Auto-generate secrets
    warn "Generating random passwords..."
    gen_pw() { openssl rand -base64 24 | tr -d '=+/' | head -c 24; }

    local wazuh_api_pw=$(gen_pw)
    local wazuh_idx_pw=$(gen_pw)
    local wazuh_dash_pw=$(gen_pw)
    local postgres_pw=$(gen_pw)
    local redis_pw=$(gen_pw)
    local cluster_key=$(openssl rand -base64 32)

    sed -i.tmp "s|WAZUH_API_PASSWORD=.*|WAZUH_API_PASSWORD=${wazuh_api_pw}|" "$ENV_FILE"
    sed -i.tmp "s|WAZUH_INDEXER_PASSWORD=.*|WAZUH_INDEXER_PASSWORD=${wazuh_idx_pw}|" "$ENV_FILE"
    sed -i.tmp "s|WAZUH_DASHBOARD_PASSWORD=.*|WAZUH_DASHBOARD_PASSWORD=${wazuh_dash_pw}|" "$ENV_FILE"
    sed -i.tmp "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${postgres_pw}|" "$ENV_FILE"
    sed -i.tmp "s|REDIS_PASSWORD=.*|REDIS_PASSWORD=${redis_pw}|" "$ENV_FILE"
    sed -i.tmp "s|WAZUH_CLUSTER_KEY=.*|WAZUH_CLUSTER_KEY=${cluster_key}|" "$ENV_FILE"
    rm -f "${ENV_FILE}.tmp"

    ok "Generated random passwords for Wazuh, Postgres, Redis"

    # Auto-detect host LAN IP
    local host_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' | head -1)
    if [ -n "$host_ip" ]; then
        sed -i.tmp "s|WAZUH_MANAGER_EXTERNAL_IP=.*|WAZUH_MANAGER_EXTERNAL_IP=${host_ip}|" "$ENV_FILE"
        rm -f "${ENV_FILE}.tmp"
        ok "Detected host LAN IP: ${host_ip}"
    fi

    echo ""
    warn "REQUIRED: Edit .env and add your LLM API keys:"
    echo -e "   ${C}GROQ_API_KEY${RST}   = https://console.groq.com/keys"
    echo -e "   ${C}GEMINI_API_KEY${RST} = https://aistudio.google.com/app/apikey"
    echo ""
    read -p "Press Enter once you've added your API keys to .env, or Ctrl+C to abort... " _
}

# ─── Step 3: SSH keypair ────────────────────────────────────────────────
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
    ok "Generated new SSH keypair: $SSH_KEY"
    warn "Public key (deploy this to agents):"
    cat "$SSH_KEY.pub" | sed 's/^/    /'
}

# ─── Step 4: TLS certs ──────────────────────────────────────────────────
setup_tls_certs() {
    step "Setting up TLS certs for Wazuh"

    if [ -f "$CERT_DIR/wazuh.manager.pem" ]; then
        ok "TLS certs already present"
        return
    fi

    mkdir -p "$CERT_DIR"
    if [ -f "$ROOT/scripts/gen_certs.sh" ]; then
        bash "$ROOT/scripts/gen_certs.sh"
        ok "Generated TLS certs via scripts/gen_certs.sh"
    else
        warn "scripts/gen_certs.sh not found — Wazuh may fail to start"
        warn "You'll need to generate certs manually. See docs/CERTS.md"
    fi
}

# ─── Render config templates ────────────────────────────────────────────
render_templates() {
    step "Rendering config templates"

    # Source .env so variables are available
    set -a
    source "$ENV_FILE"
    set +a

    # Generate bcrypt hashes for Wazuh indexer users
    if [ -f "$ROOT/wazuh/config/indexer/internal_users.yml.template" ]; then
        ok "Generating bcrypt hashes for Wazuh indexer users..."
        export WAZUH_INDEXER_HASH_ADMIN=$(python3 -c "
import bcrypt, os
pw = os.environ['WAZUH_INDEXER_PASSWORD'].encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode())
" 2>/dev/null)
        export WAZUH_INDEXER_HASH_KIBANA=$(python3 -c "
import bcrypt, os
pw = os.environ['WAZUH_DASHBOARD_PASSWORD'].encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode())
" 2>/dev/null)

        if [ -z "$WAZUH_INDEXER_HASH_ADMIN" ] || [ -z "$WAZUH_INDEXER_HASH_KIBANA" ]; then
            warn "Python bcrypt not installed — falling back to Docker-based hash generation"
            warn "This requires the Wazuh indexer image (will be pulled if needed)"
            WAZUH_INDEXER_HASH_ADMIN=$(docker run --rm -i wazuh/wazuh-indexer:4.14.4                 bash -c "echo "$WAZUH_INDEXER_PASSWORD" | /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh 2>/dev/null | tail -1")
            WAZUH_INDEXER_HASH_KIBANA=$(docker run --rm -i wazuh/wazuh-indexer:4.14.4                 bash -c "echo "$WAZUH_DASHBOARD_PASSWORD" | /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh 2>/dev/null | tail -1")
            export WAZUH_INDEXER_HASH_ADMIN WAZUH_INDEXER_HASH_KIBANA
        fi
        ok "Hashes generated"
    fi

    local templates=(
        "wazuh/config/filebeat.yml.template"
        "wazuh/config/dashboard/opensearch_dashboards.yml.template"
        "wazuh/config/dashboard/wazuh.yml.template"
        "wazuh/config/indexer/internal_users.yml.template"
    )

    for tpl in "${templates[@]}"; do
        if [ -f "$ROOT/$tpl" ]; then
            local out="${tpl%.template}"
            envsubst < "$ROOT/$tpl" > "$ROOT/$out"
            ok "Rendered $out"
        fi
    done
}

# ─── Step 5: Pull Ollama model ──────────────────────────────────────────
pull_ollama_model() {
    step "Pulling Ollama fallback model"

    # Ollama runs as a container — we'll let it pull when it starts.
    # This step just logs intent.
    local model=$(grep "^OLLAMA_MODEL=" "$ENV_FILE" | cut -d= -f2)
    warn "Ollama model '$model' will be pulled after container starts"
    warn "First pull may take 5-10 minutes (model is ~2GB)"
}

# ─── Step 6: Start stack ────────────────────────────────────────────────
start_stack() {
    step "Starting Docker Compose stack"

    cd "$ROOT"

    echo "  Building images..."
    docker compose -f docker-compose.infra.yml -f docker-compose.yml build 2>&1 | tail -5

    echo ""
    echo "  Starting infrastructure (Postgres, Redis, Nginx)..."
    docker compose -f docker-compose.infra.yml up -d
    sleep 5

    echo "  Starting Wazuh..."
    cd "$ROOT/wazuh" && docker compose up -d
    cd "$ROOT"
    echo "  Waiting for Wazuh indexer/manager to initialize (60s)..."
    sleep 60

    echo "  Starting Suricata..."
    docker compose -f docker-compose.suricata.yml up -d 2>/dev/null || true

    echo "  Starting AI agents + Ansible runner + Ollama..."
    docker compose up -d
    sleep 10

    ok "Stack started"
}

# ─── Step 7: Pull Ollama model inside container ─────────────────────────
pull_ollama_inside() {
    step "Pulling Ollama model inside container"
    local model=$(grep "^OLLAMA_MODEL=" "$ENV_FILE" | cut -d= -f2)
    if docker ps | grep -q sentinel-ollama; then
        docker exec sentinel-ollama ollama pull "$model" &
        ok "Ollama pull started in background for: $model"
        ok "Monitor with: docker exec sentinel-ollama ollama list"
    fi
}

# ─── Step 8: Health checks ─────────────────────────────────────────────
check_health() {
    step "Checking service health"
    local failures=0

    check() {
        local name=$1 cmd=$2
        if eval "$cmd" >/dev/null 2>&1; then
            ok "$name is healthy"
        else
            warn "$name is not responding (may still be starting)"
            failures=$((failures+1))
        fi
    }

    local api_port=$(grep "^PORT_WAZUH_API=" "$ENV_FILE" | cut -d= -f2)
    local indexer_port=$(grep "^PORT_WAZUH_INDEXER=" "$ENV_FILE" | cut -d= -f2)
    local ai_port=$(grep "^AI_AGENTS_PORT=" "$ENV_FILE" | cut -d= -f2)
    local ansible_port=$(grep "^PORT_ANSIBLE_RUNNER=" "$ENV_FILE" | cut -d= -f2)

    check "Wazuh Indexer" "curl -sk https://localhost:${indexer_port}/_cluster/health -u admin:\$(grep WAZUH_INDEXER_PASSWORD $ENV_FILE | cut -d= -f2)"
    check "Wazuh API"     "curl -sk https://localhost:${api_port}/"
    check "AI Agents"     "curl -s http://localhost:${ai_port}/health"
    check "Ansible Runner" "curl -s http://localhost:${ansible_port}/health"

    if [ $failures -gt 0 ]; then
        warn "$failures services not healthy — they may still be initializing"
        warn "Wait 60s and run: ./setup.sh --health-check"
    fi
}

# ─── Step 9: Print next steps ──────────────────────────────────────────
print_next_steps() {
    local host_ip=$(grep "^WAZUH_MANAGER_EXTERNAL_IP=" "$ENV_FILE" | cut -d= -f2)
    local nginx_port=$(grep "^NGINX_HTTPS_PORT=" "$ENV_FILE" | cut -d= -f2)
    local dash_port=$(grep "^PORT_WAZUH_DASHBOARD=" "$ENV_FILE" | cut -d= -f2)
    local dash_user=$(grep "^WAZUH_INDEXER_USER=" "$ENV_FILE" | cut -d= -f2)
    local dash_pw=$(grep "^WAZUH_INDEXER_PASSWORD=" "$ENV_FILE" | cut -d= -f2)

    echo ""
    echo -e "${G}${B}═══════════════════════════════════════════════════════════${RST}"
    echo -e "${G}${B}  ✅ SENTINEL-AI Commander is running${RST}"
    echo -e "${G}${B}═══════════════════════════════════════════════════════════${RST}"
    echo ""
    echo -e "${B}Access URLs:${RST}"
    echo -e "  SENTINEL Chat UI:  ${C}https://${host_ip}:${nginx_port}/${RST}"
    echo -e "  Wazuh Dashboard:   ${C}https://${host_ip}:${dash_port}/${RST}  (${dash_user} / see .env)"
    echo ""
    echo -e "${B}Next steps:${RST}"
    echo -e "  ${C}1.${RST} Enroll agents on your hosts:"
    echo -e "     ${Y}python3 enroll.py${RST}"
    echo ""
    echo -e "  ${C}2.${RST} Generate the Ansible inventory:"
    echo -e "     ${Y}python3 ansible/dynamic_inventory.py${RST}"
    echo ""
    echo -e "  ${C}3.${RST} Check logs if anything misbehaves:"
    echo -e "     ${Y}docker compose logs -f ai-agents${RST}"
    echo ""
    echo -e "${B}Credentials are in .env — keep it secret, keep it safe.${RST}"
    echo ""
}

# ─── Main ───────────────────────────────────────────────────────────────
main() {
    banner

    if [ "${1:-}" = "--health-check" ]; then
        check_health
        exit 0
    fi

    check_prerequisites
    setup_env
    setup_ssh_keys
    setup_tls_certs
    render_templates
    pull_ollama_model
    start_stack
    pull_ollama_inside
    sleep 20
    check_health
    print_next_steps
}

main "$@"
