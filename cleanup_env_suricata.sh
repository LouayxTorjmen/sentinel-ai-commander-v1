#!/usr/bin/env bash
# =============================================================================
#  cleanup_env_suricata.sh
#
#  Comment out orphaned Suricata variables in .env after the container
#  was removed. Leaves variables that are still used by ai-agents.
#
#  After Docker container removal:
#    - SURICATA_INTERFACE — orphan, was used by the removed container
#    - SURICATA_MODE       — still used by ai_agents/tools/suricata_client.py
#    - SURICATA_EVE_PATH   — still used by ai_agents/tools/suricata_client.py
#
#  Behavior: comments out SURICATA_INTERFACE (preserves history), leaves
#  SURICATA_MODE and SURICATA_EVE_PATH untouched, adds a header explaining
#  the state.
#
#  Why comment out instead of delete: keeps the audit trail of what was
#  there, and if you decide to bring back per-host Suricata for some
#  reason later you can just uncomment.
#
#  Idempotent. Safe to re-run.
#  Touches .env and .env.example if both exist. Backs up both first.
# =============================================================================

set -euo pipefail

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

ORPHAN_VAR="SURICATA_INTERFACE"
KEEP_VARS=("SURICATA_MODE" "SURICATA_EVE_PATH")

cleanup_file() {
    local f="$1"
    [[ -f "$f" ]] || { warn "Skipping $f (not present)"; return 0; }

    info "Processing: $f"

    # Detect if the orphan is already commented out (idempotency check)
    if grep -qE "^[[:space:]]*#.*${ORPHAN_VAR}=" "$f"; then
        ok "  ${ORPHAN_VAR} already commented out — nothing to do"
        # Still report state of kept vars for visibility
        for v in "${KEEP_VARS[@]}"; do
            if grep -qE "^[[:space:]]*${v}=" "$f"; then
                ok "  ${v}: present (kept — still used by ai-agents)"
            fi
        done
        return 0
    fi

    # Detect orphan presence
    if ! grep -qE "^[[:space:]]*${ORPHAN_VAR}=" "$f"; then
        warn "  ${ORPHAN_VAR} not found in $f (already removed?)"
        return 0
    fi

    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    cp "$f" "${f}.bak.${ts}"
    ok "  Backup: ${f}.bak.${ts}"

    # Use sed to comment out the line, with a note inserted just above it.
    # We do this with a temp file for safety.
    local tmp
    tmp="$(mktemp)"
    awk -v var="$ORPHAN_VAR" '
        BEGIN { commented = 0 }
        # Match SURICATA_INTERFACE=... (not already commented)
        match($0, "^[[:space:]]*"var"=") && !commented {
            print "# ── ORPHANED after Docker Suricata removal (May 2026) ──"
            print "# This variable was used only by the sentinel-suricata container,"
            print "# which has been removed in favor of centralized Suricata on pfSense."
            print "# Kept commented for audit history. Safe to delete entirely."
            print "# " $0
            commented = 1
            next
        }
        { print }
    ' "$f" > "$tmp"

    # Sanity check
    if ! grep -qE "^[[:space:]]*#.*${ORPHAN_VAR}=" "$tmp"; then
        rm -f "$tmp"
        die "Failed to comment out ${ORPHAN_VAR} in $f"
    fi

    mv "$tmp" "$f"
    ok "  ${ORPHAN_VAR} commented out"

    # Report state of kept vars
    for v in "${KEEP_VARS[@]}"; do
        if grep -qE "^[[:space:]]*${v}=" "$f"; then
            ok "  ${v}: kept (still used by ai-agents)"
        else
            warn "  ${v}: not found in file — ai-agents may break"
        fi
    done
}

header "Suricata orphan cleanup"

[[ -d "$PROJECT_ROOT" ]] || die "Not a directory: $PROJECT_ROOT"
ok "Project root: $PROJECT_ROOT"

cd "$PROJECT_ROOT"

cleanup_file ".env"
cleanup_file ".env.example"

header "Verification"

for f in .env .env.example; do
    [[ -f "$f" ]] || continue
    info "$f Suricata-related lines:"
    grep -n -iE 'suricata' "$f" | sed 's/^/    /'
done

header "Done"
echo
echo "Summary:"
echo "  • SURICATA_INTERFACE: commented out (was used by removed container)"
echo "  • SURICATA_MODE: kept (used by ai_agents/tools/suricata_client.py)"
echo "  • SURICATA_EVE_PATH: kept (used by ai_agents/tools/suricata_client.py)"
echo
echo "Recommended follow-up:"
echo "  • Restart ai-agents container so it re-reads the new .env:"
echo "      docker compose restart ai-agents"
echo "  • Confirm ai-agents still healthy:"
echo "      curl -sf http://localhost:50010/health"
echo
