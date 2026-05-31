#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# SENTINEL-AI Commander :: Project bootstrap
# ─────────────────────────────────────────────────────────────────────
# Creates a project-local Python venv at ./.venv, installs all
# Python dependencies from requirements.txt, installs ansible Galaxy
# collections, and validates the environment.
#
# Idempotent: safe to re-run. Skips steps that are already done.
#
# Usage:
#   ./bootstrap.sh              # create + install + validate
#   ./bootstrap.sh --recreate   # nuke .venv and rebuild from scratch
#   ./bootstrap.sh --verify     # only run validation, don't install
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"
REQUIREMENTS="${REPO_ROOT}/requirements.txt"
ANSIBLE_REQ="${REPO_ROOT}/ansible-requirements.yml"
ANSIBLE_COLLECTIONS_DIR="${REPO_ROOT}/.ansible-collections"

# ─── Colors ───────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

hdr()   { echo -e "\n${BOLD}${CYAN}=== $* ===${RESET}"; }
ok()    { echo -e "${GREEN}+${RESET} $*"; }
warn()  { echo -e "${YELLOW}!${RESET} $*"; }
err()   { echo -e "${RED}x${RESET} $*"; }

# ─── Arg parsing ──────────────────────────────────────────────────────
RECREATE=false
VERIFY_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --recreate) RECREATE=true ;;
    --verify)   VERIFY_ONLY=true ;;
    -h|--help)
      sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) err "unknown flag: $arg"; exit 2 ;;
  esac
done

# ─── Pre-flight: required system commands ────────────────────────────
hdr "Pre-flight checks"

for cmd in python3 pip3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    err "$cmd not found on PATH"; exit 1
  fi
done
ok "python3 / pip3 present"

# Ensure venv module is callable
if ! python3 -m venv --help >/dev/null 2>&1; then
  err "python3 -m venv unavailable. On Ubuntu/Debian:"
  err "    sudo apt install python3-venv"
  exit 1
fi
ok "python3 -m venv works"

PYTHON_VER="$(python3 --version | cut -d' ' -f2)"
ok "python version: ${PYTHON_VER}"

# ─── Recreate venv if asked ──────────────────────────────────────────
if $RECREATE && [[ -d "$VENV_DIR" ]]; then
  hdr "Removing existing venv (--recreate)"
  rm -rf "$VENV_DIR"
  ok "removed ${VENV_DIR}"
fi

# ─── Create venv ─────────────────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
  hdr "Creating venv at ${VENV_DIR}"
  python3 -m venv "$VENV_DIR"
  ok "venv created"
else
  ok "venv already exists at ${VENV_DIR}"
fi

# Activate for the rest of the script
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"
ok "venv activated"

# ─── Install / upgrade Python deps ────────────────────────────────────
if ! $VERIFY_ONLY; then
  hdr "Upgrading pip + installing requirements"
  pip install --upgrade pip wheel setuptools >/dev/null
  ok "pip / wheel / setuptools upgraded"

  if [[ ! -f "$REQUIREMENTS" ]]; then
    err "requirements.txt not found at $REQUIREMENTS"
    exit 1
  fi
  pip install -r "$REQUIREMENTS"
  ok "Python deps installed"
fi

# ─── Install ansible collections into project-local path ──────────────
if ! $VERIFY_ONLY; then
  hdr "Installing ansible Galaxy collections"
  mkdir -p "$ANSIBLE_COLLECTIONS_DIR"

  if [[ ! -f "$ANSIBLE_REQ" ]]; then
    err "ansible-requirements.yml not found at $ANSIBLE_REQ"
    exit 1
  fi

  # Install to project-local path so collections travel with the repo
  ANSIBLE_COLLECTIONS_PATH="$ANSIBLE_COLLECTIONS_DIR" \
    ansible-galaxy collection install -r "$ANSIBLE_REQ" \
    -p "$ANSIBLE_COLLECTIONS_DIR"
  ok "ansible collections installed to ${ANSIBLE_COLLECTIONS_DIR}"
fi

# ─── Validate ─────────────────────────────────────────────────────────
hdr "Validating environment"

# Python imports
declare -a python_modules=(winrm pymysql ansible jmespath fastapi)
for mod in "${python_modules[@]}"; do
  if python3 -c "import ${mod}" 2>/dev/null; then
    ok "import ${mod}"
  else
    err "FAILED to import ${mod}"
  fi
done

# Tool availability
declare -a tools=(ansible ansible-playbook ansible-galaxy)
for tool in "${tools[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    ver="$($tool --version 2>/dev/null | head -1 || true)"
    ok "${tool} :: ${ver}"
  else
    err "${tool} NOT on PATH"
  fi
done

# Ansible collections
hdr "Installed ansible collections"
ANSIBLE_COLLECTIONS_PATH="$ANSIBLE_COLLECTIONS_DIR" \
  ansible-galaxy collection list 2>/dev/null | grep -E "community\.(mysql|windows|general)|ansible\.windows" || true

# ─── Final hint ───────────────────────────────────────────────────────
hdr "Done"
cat <<EOF

  ${GREEN}Environment ready.${RESET}

  To use it in your shell:

      ${BOLD}source ${VENV_DIR}/bin/activate${RESET}

  To make ansible find the collections automatically, either keep
  using this venv (the bootstrap path is already discoverable) OR
  export this once per session:

      ${BOLD}export ANSIBLE_COLLECTIONS_PATH=${ANSIBLE_COLLECTIONS_DIR}${RESET}

  Test it now:

      ${BOLD}cd ${REPO_ROOT}/ansible${RESET}
      ${BOLD}ansible -i inventory/scenario_hosts.yml all -m ping${RESET}

EOF
