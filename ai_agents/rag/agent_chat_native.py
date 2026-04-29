"""
Ollama native function-calling path for the agentic chatbot.

Talks directly to Ollama's /api/chat endpoint with the OpenAI-style
'tools' parameter. Mistral 7B v0.3 emits structured tool calls in
JSON, eliminating the prose-vs-JSON parsing fragility we hit with
the DSPy-driven ReAct path.

Same return shape as agent_chat.run_agentic_chat:
    {"answer": str, "tool_calls": [...], "iterations": int}
"""
from __future__ import annotations

import inspect
import json
import logging
import os
from typing import Any, Dict, List

import requests

from ai_agents.rag import agent_tools

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://sentinel-ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:7b")
MAX_ITERATIONS = int(os.getenv("AGENTIC_CHAT_MAX_ITERATIONS", "5"))
HTTP_TIMEOUT = int(os.getenv("OLLAMA_HTTP_TIMEOUT", "180"))


# ─── Tool schema generation ──────────────────────────────────────────


# Parameter type hints per tool. We map Python type annotations to
# JSON schema types via inspection; for plain-string args without a
# hint we default to "string".
_PY_TO_JSON_TYPE = {
    int: "integer",
    float: "number",
    bool: "boolean",
    str: "string",
    list: "array",
    dict: "object",
}


def _python_type_to_schema(annotation: Any) -> Dict[str, Any]:
    """Convert a Python type annotation to JSON schema fragment.

    Handles bare types (int, str), Optional[X], and List[X]. Falls
    back to {'type': 'string'} for anything weird.
    """
    if annotation is inspect.Parameter.empty:
        return {"type": "string"}

    # typing.Optional[X] / Union[X, None]
    origin = getattr(annotation, "__origin__", None)
    args = getattr(annotation, "__args__", ())

    if origin is type(None):  # noqa: E721
        return {"type": "null"}

    # Optional[X] is Union[X, None]
    if origin is not None and len(args) >= 1:
        non_none = [a for a in args if a is not type(None)]  # noqa: E721
        if len(non_none) == 1:
            return _python_type_to_schema(non_none[0])
        if origin in (list, tuple):
            return {"type": "array"}
        if origin is dict:
            return {"type": "object"}

    if annotation in _PY_TO_JSON_TYPE:
        return {"type": _PY_TO_JSON_TYPE[annotation]}

    return {"type": "string"}


_PARAM_HINTS = {
    "signature_contains": "Substring to match against alert signatures (e.g. 'sql', 'nmap', 'brute', 'sqli'). Use single broad keyword.",
    "path_contains":      "Substring of a file path for FIM/syscheck queries (e.g. 'hello.txt', 'passwd', '/etc/'). Use this when the user names a specific file.",
    "agent_name":         "Name of a specific Wazuh agent (e.g. 'auto-victim1-ubuntu', 'kali-agent-1'). Omit to search all agents.",
    "src_ip":             "Source IP address (e.g. '192.168.49.131').",
    "dst_ip":             "Destination IP address.",
    "dest_port":          "Destination port number (e.g. 80, 22, 443).",
    "time_window":        "OpenSearch date math: '24h', '7d', '30d', '1h', '30m'. Default '24h'. Use '7d' for recent, '30d' for any.",
    "min_level":          "Minimum Wazuh rule level 0-15 as integer. 0=info, 5=medium, 7=high, 10=critical. Default 0.",
    "limit":              "Maximum results to return as integer (1-200). Default 100.",
    "rule_groups":        "List of Wazuh rule groups to filter by (e.g. ['authentication_failed', 'syscheck']).",
    "doc_id":             "OpenSearch document ID from a prior search result.",
    "doc_index":          "OpenSearch index name from a prior search result.",
    "incident_id":        "UUID of an incident from get_incidents.",
    "severity":           "Incident severity: 'low', 'medium', 'high', 'critical'.",
    "status":             "Incident status: 'open', 'analyzing', 'closed'.",
    "kind":               "Inventory kind: 'packages', 'processes', 'ports', 'users', 'services', 'os'.",
    "contains":           "Substring filter on inventory results.",
    "query":              "Free-text query for archive search.",
    "top_n":              "Number of top results to return.",
}


def _build_tools_schema() -> List[Dict[str, Any]]:
    """Build the OpenAI-format tools array from agent_tools.TOOLS.

    Each parameter includes a 'description' string with concrete
    examples to steer smaller models away from mirroring the schema
    shape back as their argument value.
    """
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


# ─── System prompt ───────────────────────────────────────────────────


SYSTEM_PROMPT = """You are SENTINEL-AI, a SOC analyst with tools that query a Wazuh + Suricata indexer. Use function calling, not prose.

WHICH TOOL TO USE:
- search_alerts: file changes (FIM), SQL injection, scans, brute force, web attacks, anything from a specific IP/agent. THIS IS THE DEFAULT.
  - For FIM events about a SPECIFIC file (e.g. "hello.txt"): use path_contains="hello.txt", NOT signature_contains.
  - signature_contains matches rule descriptions ("File deleted", "Integrity checksum changed") not file paths.
- search_archives: only for events that did NOT trigger an alert (rare).
- count_alerts: "how many" without details.
- top_signatures: "most common" alerts.
- list_agents: enrolled hosts.
- get_incidents: triaged incidents.
- agent_inventory: what is installed on a host.

ARG RULES:
- signature_contains is ONE substring keyword. Use "sqli" not "sql injection". Use "hello.txt" not "hello.txt was deleted".
- time_window is ONE token: "24h", "7d", "30d", "1h". Default "24h".
- min_level and limit are integers, not strings.
- Omit args you don't need. Don't pass empty strings.

If a tool returns 0 results, broaden ONE filter (longer time_window OR shorter signature_contains) and retry once. After that, answer with what you found.

Answer in plain text citing real timestamps, IPs, agents, and signatures. Never invent details.
"""


# ─── Main loop ───────────────────────────────────────────────────────


def is_native_enabled(provider: str) -> bool:
    """True only if user opted in AND the call is going to Ollama."""
    if provider != "ollama":
        return False
    return os.getenv("OLLAMA_NATIVE_TOOLS", "false").lower() in ("1", "true", "yes")


def run_agentic_chat_native(
    question: str,
    seed_context: str,
    conversation_summary: str,
) -> Dict[str, Any]:
    """Ollama-native ReAct loop. Returns same shape as run_agentic_chat.

    Uses /api/chat with tools[] parameter. Mistral emits structured
    tool_calls; we execute them and feed results back as 'tool' role
    messages. Loop terminates when assistant message has no tool_calls
    (i.e. final answer) or after MAX_ITERATIONS.
    """
    tools_schema = _build_tools_schema()

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
    ]
    if conversation_summary and conversation_summary.strip():
        messages.append({"role": "system", "content": f"Prior context: {conversation_summary}"})
    if seed_context and seed_context.strip():
        messages.append({"role": "system", "content": f"Seed context (sample, not authoritative): {seed_context[:1500]}"})
    messages.append({"role": "user", "content": question})

    tool_calls_log: List[Dict[str, Any]] = []
    iteration = 0

    while iteration < MAX_ITERATIONS:
        iteration += 1
        try:
            resp = requests.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": messages,
                    "tools": tools_schema,
                    "stream": False,
                    "options": {"temperature": 0.2},
                },
                timeout=HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.warning("agent_chat_native.ollama_failed iter=%d: %s", iteration, exc)
            return {
                "answer": f"I hit an internal error talking to the local model. ({exc})",
                "tool_calls": tool_calls_log,
                "iterations": iteration,
                "error": str(exc),
            }

        message = data.get("message") or {}
        assistant_content = message.get("content", "") or ""
        tool_calls = message.get("tool_calls") or []

        logger.info(
            "agent_chat_native.iter=%d tool_calls=%d content_len=%d",
            iteration, len(tool_calls), len(assistant_content),
        )

        # No tool calls -> final answer
        if not tool_calls:
            return {
                "answer": assistant_content.strip() or "(empty response from local model)",
                "tool_calls": tool_calls_log,
                "iterations": iteration,
            }

        # Append the assistant message before tool results (Ollama expects
        # the conversation to be coherent)
        messages.append({
            "role": "assistant",
            "content": assistant_content,
            "tool_calls": tool_calls,
        })

        # Execute each tool call and append its result
        for tc in tool_calls:
            fn = tc.get("function") or {}
            name = fn.get("name", "")
            raw_args = fn.get("arguments") or {}
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args)
                except json.JSONDecodeError:
                    args = {}
            else:
                args = dict(raw_args)

            tool_result = agent_tools.call_tool(name, args)

            # Build summary + UI-friendly result (same shape as agent_chat path)
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

            result_for_ui = tool_result
            if isinstance(tool_result, dict) and tool_result.get("alerts"):
                result_for_ui = {
                    "total": tool_result.get("total"),
                    "returned": tool_result.get("returned"),
                    "digest": tool_result.get("digest"),
                    "alerts": tool_result.get("alerts", [])[:10],
                }
                if "hint" in tool_result:
                    result_for_ui["hint"] = tool_result["hint"]

            tool_calls_log.append({
                "name": name,
                "args": args,
                "result_summary": summary,
                "result": result_for_ui,
            })

            # Compress for the LLM context (same compaction as DSPy path)
            if isinstance(tool_result, dict) and tool_result.get("alerts"):
                compressed = {
                    "total": tool_result.get("total"),
                    "returned": tool_result.get("returned"),
                    "digest": tool_result.get("digest"),
                    "sample_alerts": tool_result.get("alerts", [])[:10],
                }
                if "hint" in tool_result:
                    compressed["hint"] = tool_result["hint"]
                content_for_model = json.dumps(compressed, default=str)
            else:
                content_for_model = json.dumps(tool_result, default=str)
            if len(content_for_model) > 8000:
                content_for_model = content_for_model[:8000] + "...(truncated)"

            messages.append({
                "role": "tool",
                "content": content_for_model,
            })

    # Hit iteration limit — force a final pass with no tools
    messages.append({
        "role": "user",
        "content": "You have reached the tool call limit. Please now give a final ANSWER based on the data you have gathered. Do not call any more tools.",
    })
    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "messages": messages,
                "stream": False,
                "options": {"temperature": 0.2},
            },
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        answer = (data.get("message") or {}).get("content", "")
    except Exception as exc:
        logger.warning("agent_chat_native.final_pass_failed: %s", exc)
        answer = "I couldn't formulate a complete answer within the iteration limit."

    return {
        "answer": answer.strip() or "I couldn't formulate a complete answer within the iteration limit.",
        "tool_calls": tool_calls_log,
        "iterations": iteration,
        "hit_iteration_limit": True,
    }
