#!/usr/bin/env bash
# =============================================================================
#  remove_suricata.sh
#
#  One-shot Suricata-container removal for SENTINEL-AI Commander.
#
#  What it does:
#    1. Sanity-checks: must be in the project root (docker-compose.yml present)
#    2. Stops + removes the sentinel-suricata container if running
#    3. Edits docker-compose.yml to remove the `suricata:` service block
#       (preserves volume definition, comments, and all other services)
#    4. Validates the new compose file via `docker compose config`
#    5. Verifies remaining containers still healthy
#    6. Confirms the AI agents and Wazuh manager handle the empty volume
#       gracefully (no error spam in logs)
#
#  What it does NOT do (intentionally):
#    - Touch wazuh/docker-compose.yml (the Wazuh manager keeps mounting
#      the shared volume read-only — pfSense will populate it later)
#    - Delete docker-compose.suricata.yml (kept on disk for reference)
#    - Delete the docker/suricata/ build context (kept for reference)
#    - Delete the suricata-logs Docker volume (consumers still mount it)
#    - Touch the Wazuh manager's localfile config (reused for pfSense)
#
#  Idempotent: safe to run multiple times.
#  Backups: docker-compose.yml gets a .bak.<timestamp> copy before edit.
# =============================================================================

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'
    BOLD=$'\033[1m'; CYAN=$'\033[0;36m'; RESET=$'\033[0m'
else
    GREEN=""; YELLOW=""; RED=""; BOLD=""; CYAN=""; RESET=""
fi

ok()    { echo "${GREEN}✓${RESET} $*"; }
info()  { echo "${CYAN}→${RESET} $*"; }
warn()  { echo "${YELLOW}⚠${RESET} $*"; }
fail()  { echo "${RED}✗${RESET} $*" >&2; }
die()   { fail "$*"; exit 1; }
header(){ echo; echo "${BOLD}${CYAN}── $* ──${RESET}"; }

PROJECT_ROOT="${1:-$(pwd)}"
PROJECT_ROOT="$(cd "$PROJECT_ROOT" && pwd)"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"
PYTHON_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$PYTHON_SCRIPT_DIR/remove_suricata_service.py"

# ── 1. Sanity checks ────────────────────────────────────────────────────────
header "Step 1 — Sanity checks"

[[ -f "$COMPOSE_FILE" ]] || die "Not a project root (no docker-compose.yml): $PROJECT_ROOT"
ok "Project root: $PROJECT_ROOT"

[[ -f "$PYTHON_SCRIPT" ]] || die "Python script not found: $PYTHON_SCRIPT
Place remove_suricata_service.py next to this bash script."
ok "Python edit script: $PYTHON_SCRIPT"

command -v docker >/dev/null || die "docker command not found on PATH"
ok "docker on PATH: $(docker --version | head -1)"

if ! docker info >/dev/null 2>&1; then
    die "Cannot talk to Docker daemon. Is Docker Desktop running?"
fi
ok "Docker daemon reachable"

# ── 2. Stop and remove the suricata container ──────────────────────────────
header "Step 2 — Stop and remove sentinel-suricata"

if docker ps -a --format '{{.Names}}' | grep -qx sentinel-suricata; then
    info "Container exists. Stopping…"
    docker stop sentinel-suricata >/dev/null 2>&1 || warn "stop returned non-zero (container may already be stopped)"
    info "Removing…"
    docker rm sentinel-suricata >/dev/null
    ok "sentinel-suricata removed"
else
    ok "sentinel-suricata not present (already removed or never started)"
fi

# ── 3. Edit docker-compose.yml ─────────────────────────────────────────────
header "Step 3 — Remove suricata service from docker-compose.yml"

python3 "$PYTHON_SCRIPT" "$COMPOSE_FILE" || die "Python edit failed"

# ── 4. Validate the resulting compose file ─────────────────────────────────
header "Step 4 — Validate docker-compose.yml"

cd "$PROJECT_ROOT"
if docker compose -f docker-compose.yml config >/dev/null 2>&1; then
    ok "docker compose config: OK"
else
    fail "docker compose config reports errors:"
    docker compose -f docker-compose.yml config 2>&1 | tail -20 | sed 's/^/    /'
    die "Restore from .bak.<timestamp> if needed"
fi

# Confirm suricata service is gone
if docker compose -f docker-compose.yml config --services 2>/dev/null | grep -qx suricata; then
    fail "suricata service still listed by 'docker compose config'"
    die "Edit did not take effect. Investigate."
fi
ok "Service list (compose-rendered): $(docker compose -f docker-compose.yml config --services 2>/dev/null | tr '\n' ' ')"

# Confirm suricata-logs volume is still defined
if docker compose -f docker-compose.yml config --volumes 2>/dev/null | grep -qx suricata-logs; then
    ok "suricata-logs volume still defined"
else
    warn "suricata-logs volume not in compose — Wazuh manager may fail to mount"
fi

# ── 5. Verify remaining containers are healthy ─────────────────────────────
header "Step 5 — Remaining containers"

EXPECTED=(sentinel-wazuh-manager sentinel-wazuh-indexer sentinel-wazuh-dashboard sentinel-postgres sentinel-redis sentinel-nginx sentinel-ollama sentinel-ai-agents sentinel-ansible-runner)

ALL_OK=true
for c in "${EXPECTED[@]}"; do
    state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo "missing")
    case "$state" in
        running) ok  "$c: running" ;;
        missing) warn "$c: not present (may not have been started yet)"; ALL_OK=false ;;
        *)       warn "$c: $state"; ALL_OK=false ;;
    esac
done

if $ALL_OK; then
    ok "All expected containers running"
else
    warn "Some containers not running — that may be unrelated to this cleanup"
fi

# ── 6. Resource freed ──────────────────────────────────────────────────────
header "Step 6 — Resources reclaimed"

if command -v free >/dev/null; then
    info "Current memory state:"
    free -h | sed 's/^/    /'
fi

info "Top 5 containers by memory:"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null \
    | head -1
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null \
    | tail -n +2 | sort -k3 -h -r | head -5 | sed 's/^/    /'

# ── 7. Sanity-check downstream consumers ───────────────────────────────────
header "Step 7 — Downstream consumers (Wazuh manager + ai-agents)"

# Wazuh manager: any errors related to suricata in last 50 log lines?
if docker ps --format '{{.Names}}' | grep -qx sentinel-wazuh-manager; then
    ERRS=$(docker logs sentinel-wazuh-manager --tail 50 2>&1 \
        | grep -iE 'error|critical|fatal' \
        | grep -i suricata \
        | head -5 || true)
    if [[ -n "$ERRS" ]]; then
        warn "Wazuh manager has errors mentioning suricata in recent logs:"
        echo "$ERRS" | sed 's/^/    /'
    else
        ok "Wazuh manager: no suricata-related errors in last 50 lines"
    fi
fi

# AI agents: same check
if docker ps --format '{{.Names}}' | grep -qx sentinel-ai-agents; then
    ERRS=$(docker logs sentinel-ai-agents --tail 50 2>&1 \
        | grep -iE 'error|critical|fatal|exception|traceback' \
        | grep -i suricata \
        | head -5 || true)
    if [[ -n "$ERRS" ]]; then
        warn "ai-agents has errors mentioning suricata in recent logs:"
        echo "$ERRS" | sed 's/^/    /'
    else
        ok "ai-agents: no suricata-related errors in last 50 lines"
    fi
fi

# ── Done ───────────────────────────────────────────────────────────────────
header "Done"
echo
echo "Summary:"
echo "  • sentinel-suricata container: REMOVED"
echo "  • docker-compose.yml: edited (backup saved as .bak.<timestamp>)"
echo "  • suricata-logs volume: PRESERVED (still mounted by Wazuh + ai-agents)"
echo "  • Wazuh manager localfile config: UNCHANGED (will resume reading"
echo "    when pfSense ships eve.json into the shared volume)"
echo
echo "Next session:"
echo "  • Wire pfSense Suricata's eve.json into the SOC platform"
echo "  • Two options: Wazuh agent on pfSense, or filebeat → manager"
echo
