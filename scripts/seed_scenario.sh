#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# SENTINEL-AI :: Seed attack scenario lab state
# ─────────────────────────────────────────────────────────────────────
# Wraps the docker exec call so you don't have to remember the syntax.
# Runs ansible-playbook inside sentinel-ansible-runner container.
#
# Usage:
#   ./scripts/seed_scenario.sh              # full seed
#   ./scripts/seed_scenario.sh --check      # dry-run (no changes)
#   ./scripts/seed_scenario.sh --verbose    # show -vvv output
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

CONTAINER="sentinel-ansible-runner"
INVENTORY="/ansible/inventory/scenario_hosts.yml"
PLAYBOOK="/ansible/playbooks/seed_scenario_state.yml"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

hdr()  { echo -e "\n${BOLD}${CYAN}=== $* ===${RESET}"; }
ok()   { echo -e "${GREEN}+${RESET} $*"; }
warn() { echo -e "${YELLOW}!${RESET} $*"; }
err()  { echo -e "${RED}x${RESET} $*"; }

# ─── Parse flags ─────────────────────────────────────────────────────
EXTRA_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --check)   EXTRA_ARGS+=(--check --diff) ;;
    --verbose) EXTRA_ARGS+=(-vvv) ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) err "unknown flag: $arg"; exit 2 ;;
  esac
done

# ─── Pre-flight ──────────────────────────────────────────────────────
hdr "Pre-flight"

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  err "container '$CONTAINER' not found"
  err "build + start it first:"
  err "    docker compose build ansible-runner"
  err "    docker compose up -d ansible-runner"
  exit 1
fi
ok "container '$CONTAINER' exists"

if ! docker ps --filter "name=${CONTAINER}" --filter "status=running" -q | grep -q .; then
  warn "container '$CONTAINER' is not running, starting it..."
  docker start "$CONTAINER" >/dev/null
  sleep 3
fi
ok "container running"

# Verify scenario inventory + playbook are visible inside container
if ! docker exec "$CONTAINER" test -f "$INVENTORY"; then
  err "inventory not visible inside container at $INVENTORY"
  err "did you copy scenario_hosts.yml to ./ansible/inventory/ on host?"
  exit 1
fi
if ! docker exec "$CONTAINER" test -f "$PLAYBOOK"; then
  err "playbook not visible inside container at $PLAYBOOK"
  err "did you copy seed_scenario_state.yml to ./ansible/playbooks/ on host?"
  exit 1
fi
ok "inventory + playbook visible inside container"

# Verify collections + pywinrm are installed (sanity)
if ! docker exec "$CONTAINER" python3 -c "import winrm" 2>/dev/null; then
  err "pywinrm not installed inside container"
  err "rebuild with the updated requirements.txt:"
  err "    docker compose build ansible-runner"
  err "    docker compose up -d --force-recreate ansible-runner"
  exit 1
fi
ok "pywinrm available"

if ! docker exec "$CONTAINER" ansible-galaxy collection list 2>&1 | grep -q "community.mysql"; then
  err "community.mysql collection not installed inside container"
  err "rebuild the container (see above)"
  exit 1
fi
ok "ansible collections installed"

# ─── Run ─────────────────────────────────────────────────────────────
hdr "Running seed playbook"
echo "  inventory:  $INVENTORY"
echo "  playbook:   $PLAYBOOK"
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  echo "  extra args: ${EXTRA_ARGS[*]}"
fi
echo

docker exec -it "$CONTAINER" \
  ansible-playbook \
  -i "$INVENTORY" \
  "$PLAYBOOK" \
  "${EXTRA_ARGS[@]}"

rc=$?

if [[ $rc -eq 0 ]]; then
  hdr "Done"
  ok "lab state seeded"
  echo
  echo "  lab_state.json on host: ~/sentinel-ai-commander/ansible/lab_state.json"
  echo
  echo "  Verify MySQL plant:"
  echo "    ssh -i ~/sentinel-ai-commander/ansible/keys/id_rsa root@10.50.0.13 \\"
  echo "      \"mysql -uroot -plouay -e 'SELECT id,system_name,username FROM dvwa.infra_credentials;'\""
  echo
  echo "  Verify AD plant:"
  echo "    docker exec sentinel-ansible-runner ansible -i $INVENTORY ad_hosts \\"
  echo "      -m ansible.windows.win_shell \\"
  echo "      -a \"Get-ADUser -Filter 'SamAccountName -like \\\"svc-*\\\"' -Properties Description,DoesNotRequirePreAuth,servicePrincipalName\""
  echo
else
  err "seed playbook failed with rc=$rc"
  exit $rc
fi
