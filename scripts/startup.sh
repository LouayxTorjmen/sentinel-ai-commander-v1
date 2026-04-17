#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "[STARTUP] SENTINEL-AI Commander v2 — Full Stack Deployment"
echo "==========================================================="

echo "[STARTUP] Fixing kernel parameters..."
sudo sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || true
sudo sysctl -w net.core.somaxconn=65535 >/dev/null 2>&1 || true

echo "[STARTUP] Fixing file permissions..."
bash "$PROJECT_ROOT/scripts/fix_permissions.sh" 2>/dev/null || true

echo ""
echo "[PHASE 1] Starting Wazuh stack..."
cd wazuh && docker compose --env-file ../.env up -d 2>&1 | tail -3
cd "$PROJECT_ROOT"

echo "[PHASE 1] Waiting for Wazuh indexer..."
timeout 120 bash -c 'until docker inspect --format="{{.State.Health.Status}}" sentinel-wazuh-indexer 2>/dev/null | grep -q healthy; do sleep 5; done' || true

echo ""
echo "[PHASE 2-4] Starting unified stack (infra + suricata + ai platform)..."
docker compose --env-file .env up -d 2>&1 | tail -5

echo "[STARTUP] Waiting for services..."
sleep 30

echo "[STARTUP] Restarting TLS services..."
docker restart sentinel-wazuh-dashboard sentinel-nginx 2>/dev/null || true
sleep 15

echo ""
echo "[STARTUP] Pulling Ollama fallback model..."
docker exec sentinel-ollama ollama pull llama3.2:3b 2>&1 | tail -3 || echo "[STARTUP] Ollama pull failed (will retry on first use)"

echo ""
echo "[STARTUP] Container Status:"
docker ps --format "table {{.Names}}\t{{.Status}}" | sort
echo ""
echo "==========================================================="
echo " SENTINEL-AI Commander v2 — READY"
echo ""
echo " Wazuh Dashboard:  https://localhost:50000"
echo " Nginx Proxy:      https://localhost:50021"
echo " AI API:           https://localhost:50021/api/health"
echo " RAG Chat API:     https://localhost:50021/api/chat"
echo " ML Train:         POST https://localhost:50021/api/ml/train"
echo " LLM Health:       https://localhost:50021/api/llm/health"
echo "==========================================================="
