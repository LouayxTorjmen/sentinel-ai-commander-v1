#!/bin/bash
# SENTINEL-AI — Teardown script
# Stops and removes all containers, volumes, and networks.
# Does NOT delete .env, keys, or certs (those are yours).
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

R="\033[91m"; Y="\033[93m"; G="\033[92m"; C="\033[96m"; RST="\033[0m"

echo -e "${Y}This will stop and remove ALL SENTINEL-AI containers and their data.${RST}"
echo -e "${Y}Your .env, SSH keys, TLS certs, and source code will be preserved.${RST}"
read -p "Continue? [y/N] " confirm
[ "$confirm" != "y" ] && { echo "Aborted."; exit 0; }

echo -e "\n${C}[*] Stopping compose stacks...${RST}"
docker compose down -v 2>/dev/null || true
docker compose -f docker-compose.infra.yml down -v 2>/dev/null || true
docker compose -f docker-compose.suricata.yml down -v 2>/dev/null || true
(cd wazuh && docker compose down -v 2>/dev/null || true)

echo -e "\n${C}[*] Removing any stray containers...${RST}"
for c in $(docker ps -aq --filter "name=sentinel-"); do
    docker rm -f "$c" 2>/dev/null || true
done

echo -e "\n${C}[*] Removing Sentinel volumes...${RST}"
docker volume ls -q | grep -E "^sentinel[-_]" | xargs -r docker volume rm 2>/dev/null || true

echo -e "\n${G}✓ Teardown complete.${RST}"
echo ""
echo "To start fresh: ./setup.sh"
echo "To nuke everything including keys/certs: rm -rf ansible/keys wazuh/config/certs .env"
