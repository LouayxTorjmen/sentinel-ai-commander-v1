#!/usr/bin/env bash
# =============================================================================
# SENTINEL-AI Phase 3 — Apply Changes
# Run from: ~/sentinel-ai-commander/
# =============================================================================
# Four changes, in this order:
#   1. agent_chat_native.py  (full replacement)
#   2. agent_tools.py        (append new tools + update registries)
#   3. agent_chat.py         (5-line provider detection fix)
#   4. orchestrator.py       (fix NameError bug + retire dead agents)
#   5. chat_engine.py        (fix lm scope bug in _update_summary)
# =============================================================================

set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

[[ -f ai_agents/rag/agent_chat_native.py ]] || fail "Run from ~/sentinel-ai-commander/"

# =============================================================================
# CHANGE 1 — Replace agent_chat_native.py
# =============================================================================
echo "[1/5] Replacing agent_chat_native.py..."
cp ai_agents/rag/agent_chat_native.py \
   ai_agents/rag/agent_chat_native.py.bak.$(date +%Y%m%d_%H%M%S)
# Copy the new file from wherever you saved the Phase 3 output
# cp /path/to/sentinel-phase3/changes/agent_chat_native.py \
#    ai_agents/rag/agent_chat_native.py
warn "ACTION: copy agent_chat_native.py from the Phase 3 output to ai_agents/rag/agent_chat_native.py"

# =============================================================================
# CHANGE 2 — Add new tools to agent_tools.py
# =============================================================================
echo "[2/5] Adding new tools to agent_tools.py..."

# Step 2a: Insert the new tool functions before the TOOLS dict
# The TOOLS dict starts with the line: TOOLS: Dict[str, Any] = {
# We insert the new functions just above it.
# Easiest approach: use Python to do a clean insert.

python3 << 'PYEOF'
import re

with open("ai_agents/rag/agent_tools.py", "r") as f:
    content = f.read()

# Don't apply twice
if "execute_playbook" in content:
    print("  New tools already present — skipping insert")
    exit(0)

# Find the TOOLS registry line
marker = "\nTOOLS: Dict[str, Any] = {"
idx = content.find(marker)
if idx == -1:
    print("  ERROR: could not find TOOLS dict in agent_tools.py")
    exit(1)

# Load the additions file
with open("ai_agents/rag/agent_tools_additions.py", "r") as f:
    additions = f.read()

# Strip everything from the "UPDATE THE TOOLS REGISTRY" comment onward
# (that part is instructions, not code)
stop_marker = "# ============================================================="
stop_idx = additions.find("# UPDATE THE TOOLS REGISTRY")
if stop_idx != -1:
    additions = additions[:stop_idx].rstrip()

# Insert before the TOOLS dict
new_content = content[:idx] + "\n\n" + additions.strip() + "\n" + content[idx:]

with open("ai_agents/rag/agent_tools.py", "w") as f:
    f.write(new_content)

print("  New tool functions inserted")
PYEOF

# Step 2b: Update TOOLS registry dict
python3 << 'PYEOF'
new_entries = """    # ── Phase 3 additions ─────────────────────────────────────────────
    "get_agent_details":         get_agent_details,
    "get_agent_vulnerabilities": get_agent_vulnerabilities,
    "get_wazuh_rule":            get_wazuh_rule,
    "get_fim_events":            get_fim_events,
    "execute_playbook":          execute_playbook,
    "get_active_blocks":         get_active_blocks,
    "get_sca_results":           get_sca_results,"""

with open("ai_agents/rag/agent_tools.py", "r") as f:
    content = f.read()

if "get_agent_details" in content and "execute_playbook" in content:
    # Check if already in TOOLS dict
    tools_dict_start = content.find('TOOLS: Dict[str, Any] = {')
    tools_dict_end   = content.find('\n}', tools_dict_start)
    tools_section    = content[tools_dict_start:tools_dict_end]
    if "execute_playbook" in tools_section:
        print("  TOOLS dict already updated — skipping")
        exit(0)

    # Insert before the closing brace of TOOLS
    # Find last entry: "agent_inventory": agent_inventory,
    insertion_point = '    "agent_inventory":          agent_inventory,\n}'
    new_tools_close = f'    "agent_inventory":          agent_inventory,\n{new_entries}\n}}'
    if insertion_point in content:
        content = content.replace(insertion_point, new_tools_close)
        with open("ai_agents/rag/agent_tools.py", "w") as f:
            f.write(content)
        print("  TOOLS dict updated")
    else:
        print("  WARN: could not auto-patch TOOLS dict — patch manually per patches.txt")
else:
    print("  WARN: new tool functions not found — run step 2a first")
PYEOF

# Step 2c: Update _PER_TOOL_COERCERS
python3 << 'PYEOF'
new_coercers = """    # Phase 3 additions
    "get_agent_vulnerabilities": _coerce_search_alerts_args,
    "get_fim_events":            _coerce_search_alerts_args,
    "get_active_blocks":         _coerce_search_alerts_args,
    "get_sca_results":           _coerce_search_alerts_args,"""

with open("ai_agents/rag/agent_tools.py", "r") as f:
    content = f.read()

if "get_fim_events.*_coerce" in content or "get_sca_results" in content.split("_PER_TOOL_COERCERS")[1][:500] if "_PER_TOOL_COERCERS" in content else False:
    print("  _PER_TOOL_COERCERS already updated — skipping")
    exit(0)

# Find the end of the coercers dict and insert before it
insertion_point = '    "get_incidents": _coerce_search_alerts_args,\n}'
new_coercers_block = f'    "get_incidents": _coerce_search_alerts_args,\n{new_coercers}\n}}'
if insertion_point in content:
    content = content.replace(insertion_point, new_coercers_block)
    with open("ai_agents/rag/agent_tools.py", "w") as f:
        f.write(content)
    print("  _PER_TOOL_COERCERS updated")
else:
    print("  WARN: could not auto-patch _PER_TOOL_COERCERS — patch manually per patches.txt")
PYEOF

ok "agent_tools.py updated"

# =============================================================================
# CHANGE 3 — Fix provider detection in agent_chat.py
# =============================================================================
echo "[3/5] Fixing provider detection in agent_chat.py..."
python3 << 'PYEOF'
with open("ai_agents/rag/agent_chat.py", "r") as f:
    content = f.read()

old = '''        provider = "ollama" if model_str.startswith("ollama") else (
            "groq" if model_str.startswith("groq") else (
                "gemini" if model_str.startswith("gemini") else "unknown"
            )
        )
        if agent_chat_native.is_native_enabled(provider):
            logger.info("agent_chat.routing_to_native_ollama provider=%s model=%s", provider, model_str)
            return agent_chat_native.run_agentic_chat_native(
                question=question,
                seed_context=seed_context,
                conversation_summary=conversation_summary,
            )'''

new = '''        if model_str.startswith("ollama"):
            provider = "ollama"
        elif model_str.startswith("cerebras"):
            provider = "cerebras"
        elif model_str.startswith("groq"):
            provider = "groq"
        elif model_str.startswith("gemini"):
            provider = "gemini"
        else:
            provider = "unknown"

        if agent_chat_native.is_native_enabled(provider):
            logger.info(
                "agent_chat.routing_to_native provider=%s model=%s",
                provider, model_str,
            )
            return agent_chat_native.run_agentic_chat_native(
                question=question,
                seed_context=seed_context,
                conversation_summary=conversation_summary,
                provider=provider,
            )'''

if old in content:
    content = content.replace(old, new)
    with open("ai_agents/rag/agent_chat.py", "w") as f:
        f.write(content)
    print("  Provider detection fixed")
elif "provider=provider" in content:
    print("  Already patched — skipping")
else:
    print("  WARN: could not find exact block — apply manually per patches.txt")
PYEOF
ok "agent_chat.py patched"

# =============================================================================
# CHANGE 4 — Fix orchestrator.py
# =============================================================================
echo "[4/5] Fixing orchestrator.py..."
python3 << 'PYEOF'
with open("ai_agents/agents/orchestrator/orchestrator.py", "r") as f:
    content = f.read()

# Patch A: remove broken Redis.set() referencing undefined variables
old_redis = '''        # Cache in Redis for fast API retrieval
        get_redis().set(f"incident:{incident_id}", {
            "incident_id": incident_id,
            "alert_type": log_result.get("alert_type"),
            "severity": log_result.get("severity"),
            "summary": summary,
            "analysis": ir_result.get("analysis"),
            "mitre_techniques": log_result.get("mitre_techniques"),
            "dispatch": dispatch_result,
            "risk_score": ir_result.get("risk_score"),
        })

        return {
            "incident_id": incident_id,
            "alert_type": log_result.get("alert_type"),
            "severity": log_result.get("severity"),
            "mitre_techniques": log_result.get("mitre_techniques"),
            "summary": summary,
            "analysis": ir_result.get("analysis"),
            "risk_score": ir_result.get("risk_score"),
            "dispatch": dispatch_result,
            "cves_found": cve_result.get("total", 0),
        }'''

new_redis = '''        # Cache minimal incident record (Phase 3: LLM analysis not yet wired)
        try:
            get_redis().set(f"incident:{incident_id}", {
                "incident_id": incident_id,
                "rule_id":     alert.get("rule", {}).get("id"),
                "agent":       (alert.get("agent") or {}).get("name"),
                "severity":    "medium",
                "dispatch":    dispatch_result,
                "fast_path":   False,
                "phase":       "static_only_mode",
            })
        except Exception as redis_exc:
            logger.error("orchestrator.redis.failed", incident_id=incident_id, error=str(redis_exc))

        return {
            "incident_id": incident_id,
            "dispatch":    dispatch_result,
            "fast_path":   False,
            "phase":       "static_only_mode",
        }'''

if old_redis in content:
    content = content.replace(old_redis, new_redis)
    print("  Broken Redis.set() fixed")
elif "static_only_mode" in content and "phase" in content:
    print("  Already patched — skipping Redis fix")
else:
    print("  WARN: Redis block not found as expected — check manually")

# Patch B: remove retired agent instantiation from __init__
old_init = '''        self.log_analyzer = LogAnalyzerAgent()
        self.threat_intel = ThreatIntelAgent()
        self.cve_scanner = CVEScannerAgent()
        self.incident_responder = IncidentResponderAgent()
        self.ansible_dispatch = AnsibleDispatchAgent()'''

new_init = '''        self.log_analyzer = LogAnalyzerAgent()     # kept for Phase 3 unknown-rule triage
        self.ansible_dispatch = AnsibleDispatchAgent()
        # Retired: ThreatIntelAgent (no-op), CVEScannerAgent (replaced by tool),
        # IncidentResponderAgent (redundant with chatbot reasoning)'''

if old_init in content:
    content = content.replace(old_init, new_init)
    print("  Retired agent instantiation removed from __init__")
elif "ThreatIntelAgent" not in content:
    print("  Already patched — skipping __init__ fix")
else:
    print("  WARN: __init__ block not found as expected")

with open("ai_agents/agents/orchestrator/orchestrator.py", "w") as f:
    f.write(content)
PYEOF
ok "orchestrator.py patched"

# =============================================================================
# CHANGE 5 — Fix chat_engine.py lm scope bug
# =============================================================================
echo "[5/5] Fixing chat_engine.py _update_summary lm scope bug..."
python3 << 'PYEOF'
with open("ai_agents/rag/chat_engine.py", "r") as f:
    content = f.read()

# Fix 1: method signature
old_sig = "def _update_summary(self, session_id: str, recent_messages: List[Dict], old_summary: str):"
new_sig = "def _update_summary(self, session_id: str, recent_messages: List[Dict], old_summary: str, lm=None):"

# Fix 2: lm usage inside method
old_ctx = "            self._ensure_chain()\n            with dspy.context(lm=lm):"
new_ctx = "            self._ensure_chain()\n            _lm = lm or get_lm()\n            with dspy.context(lm=_lm):"

# Fix 3: call site in chat()
old_call = "            self._update_summary(session_id, recent_messages, summary)"
new_call = "            self._update_summary(session_id, recent_messages, summary, lm=lm)"

patched = False
if old_sig in content:
    content = content.replace(old_sig, new_sig)
    patched = True
if old_ctx in content:
    content = content.replace(old_ctx, new_ctx)
    patched = True
if old_call in content:
    content = content.replace(old_call, new_call)
    patched = True

if patched:
    with open("ai_agents/rag/chat_engine.py", "w") as f:
        f.write(content)
    print("  _update_summary lm scope bug fixed")
elif "lm=lm" in content:
    print("  Already patched — skipping")
else:
    print("  WARN: could not find expected strings — apply manually per patches.txt")
PYEOF
ok "chat_engine.py patched"

# =============================================================================
# ALSO: copy agent_tools_additions.py to ai_agents/rag/ so step 2 script
# can read it (it expects the file there)
# =============================================================================
# NOTE: run this before the step above:
#   cp /path/to/sentinel-phase3/changes/agent_tools_additions.py \
#      ai_agents/rag/agent_tools_additions.py

# =============================================================================
# VERIFY
# =============================================================================
echo ""
echo "Verifying imports..."
python3 -c "
import sys
sys.path.insert(0, '.')
from ai_agents.rag.agent_tools import TOOLS
print(f'  agent_tools: {len(TOOLS)} tools registered')
expected_new = ['get_agent_details','get_agent_vulnerabilities','get_wazuh_rule',
                'get_fim_events','execute_playbook','get_active_blocks','get_sca_results']
missing = [t for t in expected_new if t not in TOOLS]
if missing:
    print(f'  MISSING from TOOLS: {missing}')
else:
    print('  All 7 new tools present in registry')
" 2>&1 || warn "Verify failed — check errors above"

echo ""
python3 -c "
from ai_agents.rag.agent_chat_native import is_native_enabled
cerebras_ok = is_native_enabled('cerebras')
groq_ok     = is_native_enabled('groq')
ollama_ok   = is_native_enabled('ollama')
print(f'  native_enabled: cerebras={cerebras_ok} groq={groq_ok} ollama={ollama_ok}')
print('  (cerebras should be True if CEREBRAS_API_KEY is set)')
" 2>&1 || warn "native check failed"

echo ""
echo "=== Restart the container to pick up all changes ==="
echo "  docker compose restart sentinel-ai-agents"
echo "  docker logs -f sentinel-ai-agents 2>&1 | grep -E 'native|provider|tool'"
echo ""
echo "=== Test native Cerebras tool calling ==="
echo "  curl -s -X POST http://localhost:8000/chat \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"message\": \"list all enrolled agents\"}' | python3 -m json.tool | grep -E 'tool_calls|provider|answer'"
