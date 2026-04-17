#!/usr/bin/env bash
# =============================================================================
#  scripts/fix_permissions.sh — Fix ALL file permissions across entire project
#  Run this once, or it runs automatically via startup.sh
# =============================================================================
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[PERMS] Fixing all file permissions..."

# ── ALL certificate and key files — world-readable ────────────────────────────
find "$PROJECT_ROOT" -type f \( -name "*.pem" -o -name "*.key" -o -name "*.crt" \) \
    -exec chmod 644 {} \; 2>/dev/null || true

# ── ALL config YAML/YML files — world-readable ───────────────────────────────
find "$PROJECT_ROOT" -type f \( -name "*.yml" -o -name "*.yaml" -o -name "*.xml" -o -name "*.conf" \) \
    -exec chmod 644 {} \; 2>/dev/null || true

# ── ALL shell scripts — executable ───────────────────────────────────────────
find "$PROJECT_ROOT/scripts" -type f -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
find "$PROJECT_ROOT/docker" -type f -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

# ── ALL directories — traversable ────────────────────────────────────────────
find "$PROJECT_ROOT/wazuh/config" -type d -exec chmod 755 {} \; 2>/dev/null || true
find "$PROJECT_ROOT/docker/nginx" -type d -exec chmod 755 {} \; 2>/dev/null || true

# ── .env files — owner read/write only ───────────────────────────────────────
find "$PROJECT_ROOT" -maxdepth 2 -name ".env" -exec chmod 600 {} \; 2>/dev/null || true

echo "[PERMS] Done. All certs=644, scripts=+x, configs=644, .env=600"
