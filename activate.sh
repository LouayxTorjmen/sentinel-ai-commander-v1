#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Convenience entry into the project venv with ansible env vars set.
# Source this (don't execute) to enter the environment:
#
#   source ./activate.sh
#
# This is shorthand for:
#   source .venv/bin/activate
#   export ANSIBLE_COLLECTIONS_PATH=$(pwd)/.ansible-collections
# ─────────────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -d "${REPO_ROOT}/.venv" ]]; then
    echo "venv not found at ${REPO_ROOT}/.venv"
    echo "Run ./bootstrap.sh first."
    return 1 2>/dev/null || exit 1
fi

# shellcheck source=/dev/null
source "${REPO_ROOT}/.venv/bin/activate"
export ANSIBLE_COLLECTIONS_PATH="${REPO_ROOT}/.ansible-collections"

echo "venv active: ${REPO_ROOT}/.venv"
echo "ANSIBLE_COLLECTIONS_PATH=${ANSIBLE_COLLECTIONS_PATH}"
