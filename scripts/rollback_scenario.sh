#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# SENTINEL-AI :: Rollback attack scenario lab state
# ─────────────────────────────────────────────────────────────────────
# Removes everything seed_scenario.sh planted:
#  - drops dvwa.infra_credentials table
#  - removes svc-legacy and svc-mssql AD accounts
#  - deletes lab_state.json
#
# Usage:
#   ./scripts/rollback_scenario.sh
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

CONTAINER="sentinel-ansible-runner"
INVENTORY="/ansible/inventory/scenario_hosts.yml"
PLAYBOOK="/ansible/playbooks/rollback_scenario_state.yml"

if ! docker ps --filter "name=${CONTAINER}" --filter "status=running" -q | grep -q .; then
    echo "container '$CONTAINER' not running, starting..."
    docker start "$CONTAINER" >/dev/null
    sleep 3
fi

docker exec -it "$CONTAINER" \
    ansible-playbook \
    -i "$INVENTORY" \
    "$PLAYBOOK"
