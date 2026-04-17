#!/usr/bin/env bash
# =============================================================================
#  scripts/gen_certs.sh — Generate all TLS certificates
#  Creates: Wazuh inter-node certs + Nginx frontend cert
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[CERTS]${NC} $*"; }
ok()   { echo -e "${GREEN}[CERTS]${NC} $*"; }
fail() { echo -e "${RED}[CERTS]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERT_DIR="$PROJECT_ROOT/wazuh/config/certs"
NGINX_CERT_DIR="$PROJECT_ROOT/docker/nginx/certs"

# Load .env
if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a; source "$PROJECT_ROOT/.env"; set +a
fi

TLS_CERT_DAYS="${TLS_CERT_DAYS:-365}"
TLS_CERT_CN="${TLS_CERT_CN:-sentinel-ai}"

# ─── Wazuh Certs ─────────────────────────────────────────────────────────────
generate_wazuh_certs() {
    info "Generating Wazuh inter-node TLS certificates..."

    mkdir -p "$CERT_DIR"
    cd "$CERT_DIR"

    # Skip if already generated
    if [ -f "root-ca.pem" ] && [ -f "wazuh.indexer.pem" ] && [ -f "wazuh.manager.pem" ]; then
        ok "Wazuh certs already exist — skipping (delete $CERT_DIR to regenerate)"
        return
    fi

    # 1. Root CA
    info "  Creating Root CA..."
    openssl genrsa -out root-ca.key 4096 2>/dev/null
    openssl req -new -x509 -sha256 -key root-ca.key -out root-ca.pem \
        -days "$TLS_CERT_DAYS" \
        -subj "/C=US/ST=SecOps/L=Sentinel/O=SENTINEL-AI/CN=SENTINEL-AI Root CA" \
        2>/dev/null

    # 2. Admin cert (for OpenSearch security plugin)
    info "  Creating admin cert..."
    openssl genrsa -out admin.key 4096 2>/dev/null
    openssl req -new -key admin.key -out admin.csr \
        -subj "/C=US/ST=SecOps/L=Sentinel/O=SENTINEL-AI/CN=admin" 2>/dev/null
    openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca.key \
        -CAcreateserial -out admin.pem -days "$TLS_CERT_DAYS" -sha256 2>/dev/null
    rm -f admin.csr

    # 3. Indexer cert
    info "  Creating indexer cert..."
    cat > indexer-ext.cnf <<EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = sentinel-wazuh-indexer
DNS.2 = wazuh.indexer
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF
    openssl genrsa -out wazuh.indexer.key 4096 2>/dev/null
    openssl req -new -key wazuh.indexer.key -out wazuh.indexer.csr \
        -subj "/C=US/ST=SecOps/L=Sentinel/O=SENTINEL-AI/CN=wazuh.indexer" 2>/dev/null
    openssl x509 -req -in wazuh.indexer.csr -CA root-ca.pem -CAkey root-ca.key \
        -CAcreateserial -out wazuh.indexer.pem -days "$TLS_CERT_DAYS" -sha256 \
        -extfile indexer-ext.cnf -extensions v3_req 2>/dev/null
    rm -f wazuh.indexer.csr indexer-ext.cnf

    # 4. Manager cert
    info "  Creating manager cert..."
    cat > manager-ext.cnf <<EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = sentinel-wazuh-manager
DNS.2 = wazuh.manager
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF
    openssl genrsa -out wazuh.manager.key 4096 2>/dev/null
    openssl req -new -key wazuh.manager.key -out wazuh.manager.csr \
        -subj "/C=US/ST=SecOps/L=Sentinel/O=SENTINEL-AI/CN=wazuh.manager" 2>/dev/null
    openssl x509 -req -in wazuh.manager.csr -CA root-ca.pem -CAkey root-ca.key \
        -CAcreateserial -out wazuh.manager.pem -days "$TLS_CERT_DAYS" -sha256 \
        -extfile manager-ext.cnf -extensions v3_req 2>/dev/null
    rm -f wazuh.manager.csr manager-ext.cnf

    # 5. Dashboard cert
    info "  Creating dashboard cert..."
    cat > dashboard-ext.cnf <<EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = sentinel-wazuh-dashboard
DNS.2 = wazuh.dashboard
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF
    openssl genrsa -out wazuh.dashboard.key 4096 2>/dev/null
    openssl req -new -key wazuh.dashboard.key -out wazuh.dashboard.csr \
        -subj "/C=US/ST=SecOps/L=Sentinel/O=SENTINEL-AI/CN=wazuh.dashboard" 2>/dev/null
    openssl x509 -req -in wazuh.dashboard.csr -CA root-ca.pem -CAkey root-ca.key \
        -CAcreateserial -out wazuh.dashboard.pem -days "$TLS_CERT_DAYS" -sha256 \
        -extfile dashboard-ext.cnf -extensions v3_req 2>/dev/null
    rm -f wazuh.dashboard.csr dashboard-ext.cnf

    # Cleanup
    rm -f root-ca.srl

    ok "Wazuh certs generated in $CERT_DIR"
}

# ─── Nginx Certs ─────────────────────────────────────────────────────────────
generate_nginx_certs() {
    info "Generating Nginx TLS certificate..."

    mkdir -p "$NGINX_CERT_DIR"

    if [ -f "$NGINX_CERT_DIR/sentinel.crt" ] && [ -f "$NGINX_CERT_DIR/sentinel.key" ]; then
        ok "Nginx cert already exists — skipping"
        return
    fi

    openssl req -x509 -nodes -days "$TLS_CERT_DAYS" \
        -newkey rsa:4096 \
        -keyout "$NGINX_CERT_DIR/sentinel.key" \
        -out "$NGINX_CERT_DIR/sentinel.crt" \
        -subj "/C=US/ST=SecOps/L=Sentinel/O=SENTINEL-AI/CN=$TLS_CERT_CN" \
        -addext "subjectAltName=DNS:$TLS_CERT_CN,DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    ok "Nginx cert generated in $NGINX_CERT_DIR"
}

# ─── Run ─────────────────────────────────────────────────────────────────────
generate_wazuh_certs
generate_nginx_certs

echo ""
ok "All certificates generated successfully."
