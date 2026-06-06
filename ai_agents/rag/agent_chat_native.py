"""
Native function-calling path for the agentic chatbot.

Three providers are supported:
  - Ollama  : uses /api/chat with OpenAI-style tools[] (original path, unchanged)
  - Cerebras: uses /v1/chat/completions (OpenAI-compat API)
  - Groq    : uses /openai/v1/chat/completions (OpenAI-compat API)

All three paths share the same tool schema builder, system prompt, and
return the same shape: {"answer": str, "tool_calls": [...], "iterations": int}

Environment flags:
  NATIVE_TOOLS_ENABLED=true   — enables native calling for Cerebras + Groq (default: true)
  OLLAMA_NATIVE_TOOLS=true    — enables native calling for Ollama (default: false, opt-in)
"""
from __future__ import annotations

import inspect
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from ai_agents.rag import agent_tools

logger = logging.getLogger(__name__)

# ── Gemini config (OpenAI-compat endpoint) ───────────────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").removeprefix("gemini/").removeprefix("models/")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"

# ── Ollama config (unchanged) ─────────────────────────────────────────────────
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://sentinel-ollama:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "mistral:7b")

# ── Cerebras config ───────────────────────────────────────────────────────────
CEREBRAS_API_KEY = os.getenv("CEREBRAS_API_KEY", "")
CEREBRAS_MODEL   = os.getenv("CEREBRAS_MODEL", "qwen-3-235b-a22b-instruct-2507")
CEREBRAS_API_URL = "https://api.cerebras.ai/v1/chat/completions"
CEREBRAS_THINKING_DISABLED = {"type": "disabled"}  # prevents reasoning tokens in output

# ── Groq config ───────────────────────────────────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL   = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

MAX_ITERATIONS = int(os.getenv("AGENTIC_CHAT_MAX_ITERATIONS", "5"))
HTTP_TIMEOUT   = int(os.getenv("NATIVE_HTTP_TIMEOUT", "60"))
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_HTTP_TIMEOUT", "180"))


# ── Tool schema generation (shared across all providers) ─────────────────────

_PY_TO_JSON_TYPE = {
    int: "integer", float: "number", bool: "boolean",
    str: "string", list: "array", dict: "object",
}


def _python_type_to_schema(annotation: Any) -> Dict[str, Any]:
    if annotation is inspect.Parameter.empty:
        return {"type": "string"}
    origin = getattr(annotation, "__origin__", None)
    args   = getattr(annotation, "__args__", ())
    if origin is not None and len(args) >= 1:
        non_none = [a for a in args if a is not type(None)]  # noqa: E721
        if len(non_none) == 1:
            return _python_type_to_schema(non_none[0])
        if origin in (list, tuple):
            # Include items field — required by Groq and strict OpenAI validators
            inner = non_none[0] if non_none else str
            inner_schema = _python_type_to_schema(inner) if inner is not str else {"type": "string"}
            return {"type": "array", "items": inner_schema}
        if origin is dict:
            return {"type": "object"}
    if annotation in _PY_TO_JSON_TYPE:
        return {"type": _PY_TO_JSON_TYPE[annotation]}
    return {"type": "string"}


_PARAM_HINTS = {
    "signature_contains": "Substring to match against alert signatures (e.g. 'sql', 'nmap', 'brute'). One broad keyword.",
    "path_contains":      "Substring of a file path for FIM queries (e.g. 'hello.txt', '/etc/'). Use for specific file questions.",
    "agent_name":         "Exact Wazuh agent name (e.g. 'srv-web', 'srv-ad-dns', 'srv-sql'). Omit to search all agents.",
    "src_ip":             "Source IP address (e.g. '10.70.0.10').",
    "dst_ip":             "Destination IP address.",
    "dest_port":          "Destination port number as integer (e.g. 80, 22, 443).",
    "time_window":        "OpenSearch date math: '24h', '7d', '30d', '1h', '30m'. Default '24h'.",
    "min_level":          "Minimum Wazuh rule level as integer 0-15. 0=info, 5=medium, 7=high, 10=critical. Default 0.",
    "limit":              "Maximum results to return as integer (1-200). Default 100.",
    "rule_groups":        "List of Wazuh rule groups e.g. ['authentication_failed', 'syscheck'].",
    "doc_id":             "OpenSearch document ID from a prior search result.",
    "doc_index":          "OpenSearch index name from a prior search result.",
    "incident_id":        "UUID of an incident from get_incidents.",
    "severity":           "Incident severity: 'low', 'medium', 'high', 'critical'.",
    "status":             "Incident status: 'open', 'analyzing', 'closed'.",
    "kind":               "Inventory kind: 'packages', 'processes', 'ports', 'users', 'services'.",
    "contains":           "Substring filter on inventory item names.",
    "query":              "Free-text query string for archive search.",
    "top_n":              "Number of top results to return as integer.",
    "rule_id":            "Wazuh rule ID as string (e.g. '100601', '550').",
    "playbook":           "Ansible playbook name (e.g. 'block_ip', 'incident_response', 'harden_nginx_tls').",
    "target_host":        "Wazuh agent name to run the playbook on (e.g. 'srv-web'). Never 'all'.",
    "confirmed":          "False = preview/confirmation prompt, True = actually execute. Always False on first call.",
    "source_ip":          "Source IP address to block (required for block_ip and similar playbooks).",
    "reason":             "Human-readable reason for the action (for audit log).",
}


def _build_tools_schema() -> List[Dict[str, Any]]:
    """Build OpenAI-format tools array from agent_tools.TOOLS."""
    schemas: List[Dict[str, Any]] = []
    for name, fn in agent_tools.TOOLS.items():
        doc = (fn.__doc__ or "").strip()
        description = doc.split("\n\n")[0].replace("\n", " ").strip()[:300]
        sig = inspect.signature(fn)
        properties: Dict[str, Any] = {}
        required: List[str] = []
        for pname, p in sig.parameters.items():
            schema = _python_type_to_schema(p.annotation)
            hint = _PARAM_HINTS.get(pname)
            if hint:
                schema["description"] = hint
            properties[pname] = schema
            if p.default is inspect.Parameter.empty:
                required.append(pname)
        schemas.append({
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        })
    return schemas


# ── Shared system prompt ──────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are SENTINEL-AI, a SOC analyst assistant. Be concise and direct.
RESPONSE RULES:
- No preamble ("Sure!", "Great question", "I'll help you with that")
- No closing remarks or suggestions unless asked
- Never repeat information already shown in the same response
- If the answer is a single fact (number, name, status), just state it
- For agent counts: ALWAYS read the 'summary', 'active_count', 'disconnected_count' fields directly from the tool result. NEVER count agents manually from a list.
- For alerts: markdown table with columns: Timestamp (UTC) | Rule | Description | Agent. Omit src_ip/dst_ip columns entirely if all values are null or empty. Never show null values.
- For tables: use markdown table format, max 5 rows unless more requested
- For explanations: 2-3 sentences max unless asked for more detail
- For playbook execution: show confirmation block only, nothing else

You have tools that query a Wazuh + Suricata SIEM.

CRITICAL — TIME AND DATA RULES:
- NEVER say "last X hours/minutes" unless you verified the actual timestamps
- Always state the EXACT timestamp range from the tool result (e.g. "from 2026-06-03 18:46 to 20:35 UTC")
- If timestamps are days old, say so — do not reframe them as recent
- Wazuh stores historical data — results may be from days or weeks ago
- Never infer recency — read the timestamps and report them literally Your lab network:
- Network topology is loaded dynamically from Wazuh at query time
- Management subnets (never block): configured via SENTINEL_MANAGEMENT_SUBNETS env
- Attacker/red-team subnets: configured via SENTINEL_ATTACKER_SUBNETS env
- For current agent list: use list_agents() or get_agent_details()

TOOL SELECTION:
- search_alerts: primary tool for ALL security questions (alerts, attacks, FIM, scans, SSH, web attacks, Kerberos)
  - For "what happened / summary / overview" questions: ALWAYS add min_level=7 to filter noise
  - For "any attacks / active threats" questions: use min_level=10
  - For FIM/file questions: use path_contains="filename", NOT signature_contains
  - signature_contains matches rule descriptions, not file paths
  - NEVER call search_alerts without min_level for broad summary questions — 10K noise alerts are useless
  - For FIM/file questions: use path_contains="filename", NOT signature_contains
  - signature_contains matches rule descriptions, not file paths
- search_archives: ONLY for events that did NOT trigger an alert (rare)
- count_alerts: "how many" without details
- top_signatures: "most common" alert types
- list_agents: enrolled hosts
- get_agent_details: status, OS, last seen for a specific agent
- get_agent_vulnerabilities: CVEs on a specific agent
- get_wazuh_rule: why did rule X fire? what does it detect?
- get_fim_events: file integrity changes on a specific path
- get_incidents: triaged incidents from the orchestrator database
- agent_inventory: installed packages, running processes, open ports
- get_sca_results: CIS benchmark compliance results
- get_active_blocks: what IPs are currently blocked, why was X banned
- execute_playbook: run a response playbook (ALWAYS call with confirmed=False first)

EXECUTE_PLAYBOOK RULES (critical):
1. ALWAYS call execute_playbook with confirmed=False first — this shows the user what will happen
2. Present the confirmation message to the user word for word
3. ONLY call with confirmed=True after the user explicitly says 'confirm', 'yes', 'do it', or similar
4. Never skip the confirmation step, even if the user seems sure

ARG RULES:
- time_window: one token '24h', '7d', '30d'. Default '24h'
- min_level and limit: integers, not strings. Never pass null
- Omit args you don't need. Never pass empty strings
- agent_name: use list_agents() to get current enrolled agent names (environment-specific)

CRITICAL TOPOLOGY RULE — port scans and network attacks:
  Suricata runs on the GATEWAY AGENT, NOT on victim hosts.
  Use get_agent_details() or list_agents() to identify the gateway (look for 'fw'/'firewall'/'pfsense' in name).
  Port scans targeting a victim host are stored as alerts FROM the gateway agent WITH dst_ip = victim IP.
  To find "what ports were scanned on agent X":
    CORRECT: look up agent X's IP with get_agent_details(agent_X), then search_alerts(dst_ip=<that_ip>)
    WRONG:   search_alerts(agent_name=agent_X, rule_groups=["suricata"])

If a tool returns 0 results, broaden ONE filter and retry once. Then answer with what you found.
Always cite real data: timestamps, IPs, agent names, rule IDs. Never invent details.
"""


# ── Response parsing helpers ──────────────────────────────────────────────────

def _parse_tool_calls_openai(raw_tool_calls: List[Dict]) -> List[Tuple[str, str, dict]]:
    """Parse OpenAI-format tool_calls into (call_id, name, args) tuples.

    OpenAI tool_calls: [{id, type, function: {name, arguments (JSON string)}}]
    """
    parsed = []
    for tc in raw_tool_calls or []:
        fn = tc.get("function") or {}
        call_id = tc.get("id", f"call_{int(time.time())}")
        name = fn.get("name", "")
        raw_args = fn.get("arguments") or "{}"
        # arguments is a JSON string in OpenAI format
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args)
            except json.JSONDecodeError:
                args = {}
        else:
            args = dict(raw_args)
        parsed.append((call_id, name, args))
    return parsed


def _parse_tool_calls_ollama(raw_tool_calls: List[Dict]) -> List[Tuple[str, str, dict]]:
    """Parse Ollama-format tool_calls into (call_id, name, args) tuples.

    Ollama tool_calls: [{function: {name, arguments (already a dict)}}]
    No id field — we generate one.
    """
    parsed = []
    for i, tc in enumerate(raw_tool_calls or []):
        fn = tc.get("function") or {}
        call_id = f"ollama_{i}_{int(time.time())}"
        name = fn.get("name", "")
        raw_args = fn.get("arguments") or {}
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args)
            except json.JSONDecodeError:
                args = {}
        else:
            args = dict(raw_args)
        parsed.append((call_id, name, args))
    return parsed


def _execute_tool_calls(
    parsed_calls: List[Tuple[str, str, dict]],
) -> Tuple[List[Dict], List[Dict]]:
    """Execute a list of parsed tool calls.

    Returns:
        tool_result_messages: list of {role, tool_call_id, content} for next API call
        tool_calls_log: list of {name, args, result_summary, result} for UI
    """
    tool_result_messages = []
    tool_calls_log = []

    for call_id, name, args in parsed_calls:
        tool_result = agent_tools.call_tool(name, args)

        # Build UI summary
        if isinstance(tool_result, dict):
            if "alerts" in tool_result:
                summary = f"{tool_result.get('returned', 0)}/{tool_result.get('total', 0)} alerts"
            elif "signatures" in tool_result:
                summary = f"{len(tool_result.get('signatures', []))} signatures"
            elif "agents" in tool_result:
                summary = f"{len(tool_result.get('agents', []))} agents"
            elif "total" in tool_result:
                summary = f"count={tool_result['total']}"
            elif "error" in tool_result:
                summary = f"error: {tool_result['error']}"
            else:
                summary = "ok"
        else:
            summary = "ok"

        # Compact result for the model context
        result_for_model = tool_result
        if isinstance(tool_result, dict) and tool_result.get("alerts"):
            result_for_model = {
                "total":       tool_result.get("total"),
                "returned":    tool_result.get("returned"),
                "digest":      tool_result.get("digest"),
                "sample_alerts": tool_result.get("alerts", [])[:10],
            }
            if "hint" in tool_result:
                result_for_model["hint"] = tool_result["hint"]

        content_str = json.dumps(result_for_model, default=str)
        if len(content_str) > 8000:
            content_str = content_str[:8000] + "...(truncated)"

        # UI-friendly result (cap at 10 alerts)
        result_for_ui = tool_result
        if isinstance(tool_result, dict) and tool_result.get("alerts"):
            result_for_ui = {
                "total":       tool_result.get("total"),
                "returned":    tool_result.get("returned"),
                "digest":      tool_result.get("digest"),
                "alerts":      tool_result.get("alerts", [])[:10],
            }
            if "hint" in tool_result:
                result_for_ui["hint"] = tool_result["hint"]

        tool_calls_log.append({
            "name":           name,
            "args":           args,
            "result_summary": summary,
            "result":         result_for_ui,
        })

        tool_result_messages.append({
            "role":         "tool",
            "tool_call_id": call_id,
            "content":      content_str,
        })

    return tool_result_messages, tool_calls_log


# ── Provider availability ─────────────────────────────────────────────────────

def is_native_enabled(provider: str) -> bool:
    """True when the given provider supports native function calling and it's enabled.

    Cerebras and Groq are enabled by default (NATIVE_TOOLS_ENABLED=true).
    Ollama requires explicit opt-in (OLLAMA_NATIVE_TOOLS=true).
    """
    if provider == "ollama":
        return os.getenv("OLLAMA_NATIVE_TOOLS", "false").lower() in ("1", "true", "yes")
    if provider == "cerebras":
        enabled = os.getenv("NATIVE_TOOLS_ENABLED", "true").lower() in ("1", "true", "yes")
        return enabled and bool(CEREBRAS_API_KEY)
    if provider == "groq":
        enabled = os.getenv("NATIVE_TOOLS_ENABLED", "true").lower() in ("1", "true", "yes")
        return enabled and bool(GROQ_API_KEY)
    if provider == "gemini":
        enabled = os.getenv("NATIVE_TOOLS_ENABLED", "true").lower() in ("1", "true", "yes")
        return enabled and bool(GEMINI_API_KEY)
    return False


# ── Main entrypoint ───────────────────────────────────────────────────────────

def run_agentic_chat_native(
    question: str,
    seed_context: str,
    conversation_summary: str,
    provider: Optional[str] = None,
) -> Dict[str, Any]:
    """Native function-calling ReAct loop. Routes to the correct provider.

    Returns same shape as agent_chat.run_agentic_chat:
        {"answer": str, "tool_calls": [...], "iterations": int}
    """
    # Build cascade order based on requested provider
    if provider == "ollama":
        return _run_ollama(question, seed_context, conversation_summary)

    cascade = []
    if provider == "cerebras":
        cascade = ["cerebras", "groq", "gemini"]
    elif provider == "groq":
        cascade = ["groq", "cerebras", "gemini"]
    elif provider == "gemini":
        cascade = ["gemini", "cerebras", "groq"]
    else:
        if CEREBRAS_API_KEY and is_native_enabled("cerebras"):
            cascade.append("cerebras")
        if GROQ_API_KEY and is_native_enabled("groq"):
            cascade.append("groq")
        if GEMINI_API_KEY and is_native_enabled("gemini"):
            cascade.append("gemini")

    last_result = None
    for p in cascade:
        if p == "cerebras" and not CEREBRAS_API_KEY:
            continue
        if p == "groq" and not GROQ_API_KEY:
            continue
        if p == "gemini" and not GEMINI_API_KEY:
            continue
        result = _run_openai_compat(question, seed_context, conversation_summary, p)
        last_result = result
        # If not a rate-limit or API error, return immediately
        answer = result.get("answer", "")
        if "429" not in answer and "error calling" not in answer.lower():
            return result
        logger.warning("agent_chat_native.cascade_fallback from=%s reason=%s", p, answer[:80])

    # All cloud providers rate-limited — return best error rather than hanging on Ollama
    # Ollama is too slow (60-180s) for interactive SOC chat
    if last_result:
        last_result["answer"] = (
            "All cloud providers are temporarily rate-limited. "
            "Please wait 60 seconds and try again."
        )
        return last_result

    return {"answer": "All providers unavailable.", "tool_calls": [], "iterations": 0}


# ── OpenAI-compatible path (Cerebras + Groq) ──────────────────────────────────

def _run_openai_compat(
    question: str,
    seed_context: str,
    conversation_summary: str,
    provider: str,
) -> Dict[str, Any]:
    """ReAct loop using OpenAI-compatible chat completions API.

    Handles Cerebras (api.cerebras.ai) and Groq (api.groq.com).
    Both accept identical payloads; only the endpoint URL and API key differ.
    """
    if provider == "cerebras":
        api_url   = CEREBRAS_API_URL
        api_key   = CEREBRAS_API_KEY
        model     = CEREBRAS_MODEL
        # Note: thinking/reasoning disable not supported on all Cerebras models
        # gpt-oss-120b returns None content if thinking param is sent
        payload_extras = {}
    elif provider == "gemini":
        api_url   = GEMINI_API_URL
        api_key   = GEMINI_API_KEY
        model     = GEMINI_MODEL
    else:  # groq
        api_url   = GROQ_API_URL
        api_key   = GROQ_API_KEY
        model     = GROQ_MODEL

    tools_schema = _build_tools_schema()
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
    ]
    if conversation_summary and conversation_summary.strip():
        messages.append({
            "role":    "system",
            "content": f"Conversation context: {conversation_summary[:1500]}",
        })
    if seed_context and seed_context.strip():
        messages.append({
            "role":    "system",
            "content": f"Seed context (sample, not authoritative): {seed_context[:1500]}",
        })
    messages.append({"role": "user", "content": question})

    tool_calls_log: List[Dict[str, Any]] = []
    iteration = 0

    while iteration < MAX_ITERATIONS:
        iteration += 1
        try:
            resp = requests.post(
                api_url,
                headers=headers,
                json={
                    "model":       model,
                    "messages":    messages,
                    **(payload_extras if "payload_extras" in locals() else {}),
                    "tools":       tools_schema,
                    "tool_choice": "auto",
                    "temperature": 0,
                    "max_tokens":  4096,
                },
                timeout=HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            # Log response body for 4xx errors to aid debugging
            body = ""
            if hasattr(exc, "response") and exc.response is not None:
                try:
                    body = exc.response.text[:300]
                except Exception:
                    pass
            logger.warning(
                "agent_chat_native.%s_failed iter=%d: %s %s", provider, iteration, exc, body
            )
            return {
                "answer":     f"I hit an error calling {provider}. ({exc})",
                "tool_calls": tool_calls_log,
                "iterations": iteration,
                "error":      str(exc),
            }

        choice  = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        finish_reason = choice.get("finish_reason", "")

        assistant_content = message.get("content") or ""
        import re as _re
        assistant_content = _re.sub(r"<think>.*?</think>", "", assistant_content, flags=_re.DOTALL).strip()
        raw_tool_calls    = message.get("tool_calls") or []

        logger.info(
            "agent_chat_native.%s iter=%d finish_reason=%s tool_calls=%d content_len=%d",
            provider, iteration, finish_reason, len(raw_tool_calls), len(assistant_content),
        )

        # No tool calls → final answer
        if not raw_tool_calls or finish_reason == "stop":
            return {
                "answer":     assistant_content.strip() or "(empty response)",
                "tool_calls": tool_calls_log,
                "iterations": iteration,
            }

        # Append assistant message (with tool_calls list) before tool results
        # OpenAI spec requires the assistant message to carry the tool_calls array
        messages.append({
            "role":       "assistant",
            "content":    assistant_content,
            "tool_calls": raw_tool_calls,
        })

        # Parse and execute tool calls
        parsed = _parse_tool_calls_openai(raw_tool_calls)
        tool_result_msgs, batch_log = _execute_tool_calls(parsed)
        tool_calls_log.extend(batch_log)

        # Append tool results — OpenAI format requires tool_call_id
        messages.extend(tool_result_msgs)

    # Hit MAX_ITERATIONS — force a final pass with no tools
    messages.append({
        "role":    "user",
        "content": (
            "You have reached the tool call limit. Provide a final answer "
            "based on the data you have gathered. Do not call any more tools."
        ),
    })
    try:
        resp = requests.post(
            api_url,
            headers=headers,
            json={
                "model":       model,
                "messages":    messages,
                **(payload_extras if "payload_extras" in locals() else {}),
                "temperature": 0,
                "max_tokens":  2048,
                # Deliberately omit tools so the model can't call any more
            },
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        data    = resp.json()
        choice  = (data.get("choices") or [{}])[0]
        _msg    = (choice.get("message") or {})
        answer  = _msg.get("content") or ""
        import re as _re2
        answer = _re2.sub(r"<think>.*?</think>", "", answer, flags=_re2.DOTALL).strip()
    except Exception as exc:
        logger.warning("agent_chat_native.%s.final_pass_failed: %s", provider, exc)
        answer = "I couldn't formulate a complete answer within the iteration limit."

    return {
        "answer":              answer.strip() or "I couldn't formulate a complete answer within the iteration limit.",
        "tool_calls":          tool_calls_log,
        "iterations":          iteration,
        "hit_iteration_limit": True,
    }


# ── Ollama path (unchanged from original) ────────────────────────────────────

def _run_ollama(
    question: str,
    seed_context: str,
    conversation_summary: str,
) -> Dict[str, Any]:
    """Ollama-native ReAct loop. Identical to the original implementation."""
    tools_schema = _build_tools_schema()

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
    ]
    if conversation_summary and conversation_summary.strip():
        messages.append({
            "role":    "system",
            "content": f"Prior context: {conversation_summary}",
        })
    if seed_context and seed_context.strip():
        messages.append({
            "role":    "system",
            "content": f"Seed context (sample, not authoritative): {seed_context[:1500]}",
        })
    messages.append({"role": "user", "content": question})

    tool_calls_log: List[Dict[str, Any]] = []
    iteration = 0

    while iteration < MAX_ITERATIONS:
        iteration += 1
        try:
            resp = requests.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model":    OLLAMA_MODEL,
                    "messages": messages,
                    "tools":    tools_schema,
                    "stream":   False,
                    "options":  {"temperature": 0},
                },
                timeout=HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.warning("agent_chat_native.ollama_failed iter=%d: %s", iteration, exc)
            return {
                "answer":     f"I hit an error talking to the local model. ({exc})",
                "tool_calls": tool_calls_log,
                "iterations": iteration,
                "error":      str(exc),
            }

        message         = data.get("message") or {}
        assistant_content = message.get("content", "") or ""
        raw_tool_calls  = message.get("tool_calls") or []

        logger.info(
            "agent_chat_native.ollama iter=%d tool_calls=%d content_len=%d",
            iteration, len(raw_tool_calls), len(assistant_content),
        )

        if not raw_tool_calls:
            return {
                "answer":     assistant_content.strip() or "(empty response from local model)",
                "tool_calls": tool_calls_log,
                "iterations": iteration,
            }

        messages.append({
            "role":       "assistant",
            "content":    assistant_content,
            "tool_calls": raw_tool_calls,
        })

        parsed = _parse_tool_calls_ollama(raw_tool_calls)
        tool_result_msgs, batch_log = _execute_tool_calls(parsed)
        tool_calls_log.extend(batch_log)

        # Ollama tool result messages don't need tool_call_id
        for msg in tool_result_msgs:
            messages.append({
                "role":    "tool",
                "content": msg["content"],
            })

    # Hit iteration limit
    messages.append({
        "role":    "user",
        "content": "You have reached the tool call limit. Please give a final ANSWER based on the data you have gathered.",
    })
    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model":    OLLAMA_MODEL,
                "messages": messages,
                "stream":   False,
                "options":  {"temperature": 0},
            },
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        answer = (resp.json().get("message") or {}).get("content", "")
    except Exception as exc:
        logger.warning("agent_chat_native.ollama.final_pass_failed: %s", exc)
        answer = "I couldn't formulate a complete answer within the iteration limit."

    return {
        "answer":              answer.strip() or "I couldn't formulate a complete answer within the iteration limit.",
        "tool_calls":          tool_calls_log,
        "iterations":          iteration,
        "hit_iteration_limit": True,
    }
