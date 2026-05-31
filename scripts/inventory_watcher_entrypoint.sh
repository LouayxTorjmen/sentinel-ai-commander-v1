# ─────────────────────────────────────────────────────────────────────
#  inventory_watcher_entrypoint.sh
#
#  Drop-in entrypoint addition for the sentinel-ansible-runner container.
#  Runs the inventory watcher as a background process alongside the
#  existing runner API. Replaces the bare API command in the container's
#  CMD/ENTRYPOINT.
#
#  Mount/copy this script into the container at /usr/local/bin/ and
#  update the Dockerfile or docker-compose.yml so it's executed as the
#  container's PID 1.
# ─────────────────────────────────────────────────────────────────────
#!/bin/bash
set -eo pipefail

INVENTORY_PATH="${INVENTORY_PATH:-/ansible/inventory/hosts.ini}"
INVENTORY_INTERVAL="${INVENTORY_INTERVAL:-60}"
RUNNER_API_BIN="${RUNNER_API_BIN:-/usr/local/bin/runner_api.py}"
DYN_INV_BIN="${DYN_INV_BIN:-/ansible/dynamic_inventory.py}"

log() { echo "[entrypoint $(date +%H:%M:%S)] $*"; }

# 1. One-shot inventory refresh BEFORE the API starts.
#    Ensures the inventory file exists so the first playbook can run.
log "running initial inventory refresh"
python3 "$DYN_INV_BIN" --once || log "WARN: initial refresh failed; will retry in watcher"

# 2. Start the inventory watcher in the background.
log "starting inventory watcher (interval=${INVENTORY_INTERVAL}s)"
python3 "$DYN_INV_BIN" --watch --interval "$INVENTORY_INTERVAL" \
    > /var/log/inventory_watcher.log 2>&1 &
WATCHER_PID=$!
log "inventory watcher pid=$WATCHER_PID"

# 3. Start the runner API in the foreground (PID 1 keeps the container alive).
log "starting runner API from ${RUNNER_WORKDIR:-/app}"
cd "${RUNNER_WORKDIR:-/app}"
exec python3 "$RUNNER_API_BIN"
