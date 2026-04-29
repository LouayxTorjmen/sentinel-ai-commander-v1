"""
Agentic chat layer for SENTINEL-AI Commander.

Layered on top of the existing single-shot RAG. Activated by setting
USE_AGENTIC_CHAT=true in the environment. Falls back to the original
single-shot path when the env var is unset or false.

Design:
  1. The user asks a question.
  2. The retriever runs once to build a small SEED context (3-5 alerts)
     so the LLM has something to anchor on.
  3. A DSPy signature with an explicit tool catalogue prompts the LLM
     to either ANSWER directly or emit a TOOL_CALL.
  4. If TOOL_CALL, we execute it via agent_tools.call_tool, append the
     result to the conversation, and loop.
  5. Loop terminates on ANSWER or after MAX_ITERATIONS (configurable).

We deliberately use a lightweight manual ReAct loop instead of
dspy.ReAct because:
  - DSPy ReAct's API has shifted across versions
  - Manual control gives us better logging + debug visibility
  - The patterns map 1:1 to Anthropic/OpenAI tool-use prompts if you
    later want to swap out DSPy
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import dspy

from ai_agents.rag import agent_tools

logger = logging.getLogger(__name__)


MAX_ITERATIONS = int(os.getenv("AGENTIC_CHAT_MAX_ITERATIONS", "5"))


def is_enabled() -> bool:
    """Read the env var fresh each call so users can flip without restart."""
    return os.getenv("USE_AGENTIC_CHAT", "false").lower() in ("1", "true", "yes")


# ─── DSPy Signatures ──────────────────────────────────────────────────


class AgenticSecurityChatSignature(dspy.Signature):
    """You are SENTINEL-AI, a SOC analyst with tools to query a Wazuh +
    Suricata indexer.

    seed_context is a SAMPLE of recent alerts, not authoritative.

    Output format (one of these two prefixes only):
      ANSWER: <reply citing specific facts from data>
      TOOL_CALL: <one JSON on same line: {"name":"search_alerts","args":{...}}>

    CALL A TOOL when: user asks "all/every/list/which/how many/what ports/IPs",
    seed shows same signature repeated, user asks about specific fields not
    in seed, or user references a specific event burst.

    ANSWER directly when: casual chat, OR you already have sufficient data
    from a prior tool call (returned > 0).

    Tool args:
    - time_window: "24h" default. "30d" for ever/any. "1h" only if user said
      "in the last hour".
    - limit: 50 default, up to 200 for "all".
    - signature_contains: BROAD term. "scan" not "nmap" (matches all SCAN
      signatures).

    CRITICAL — avoid loops:
    - If a previous call returned > 0 alerts, the data is in tool_history.
      Do NOT repeat the same tool with same args. Either:
        (a) refine with NEW args (different filter, broader signature, etc), or
        (b) ANSWER now using the data you have.
    - If a call returned total=0 (or hint field), broaden BEFORE retrying.
      Never repeat identical 0-hit args.

    Always cite specific facts: timestamps, IPs, ports, signatures, agent
    names. Never invent details.

    Tool result format: search_alerts returns total + returned + digest +
    sample_alerts. The 'digest' has aggregated counts (signatures, agents,
    src_ips, dst_ips, dest_ports, time_range) — use this to answer
    'which/how many/list' questions efficiently. Use 'sample_alerts' for
    concrete examples (first 10 alerts). The full alert list is NOT
    returned to you to keep context small.
    """

    question: str = dspy.InputField(desc="The user's message")
    seed_context: str = dspy.InputField(desc="Small initial context from RAG retriever")
    conversation_summary: str = dspy.InputField(desc="Summary of prior turns")
    tool_catalogue: str = dspy.InputField(desc="List of available tools and their parameters")
    tool_history: str = dspy.InputField(desc="Previous tool calls in this turn and their results")
    response: str = dspy.OutputField(
        desc="Either 'ANSWER: <your reply>' or 'TOOL_CALL: <json>'. Must start with one of these prefixes."
    )


# ─── ReAct loop ──────────────────────────────────────────────────────


_chain: Optional[dspy.Module] = None


def _get_chain() -> dspy.Module:
    global _chain
    if _chain is None:
        _chain = dspy.ChainOfThought(AgenticSecurityChatSignature)
    return _chain


_TOOL_CALL_RE = re.compile(r"TOOL_CALL\s*:\s*(\{.*\})", re.DOTALL)
_ANSWER_RE = re.compile(r"ANSWER\s*:\s*(.*)", re.DOTALL)


def _parse_response(raw: str) -> Tuple[str, Any]:
    """Returns (kind, payload). kind is 'answer' or 'tool_call' or 'malformed'."""
    if not raw:
        return ("malformed", "empty response")

    # Try TOOL_CALL first (more specific)
    m = _TOOL_CALL_RE.search(raw)
    if m:
        try:
            obj = json.loads(m.group(1).strip())
            if not isinstance(obj, dict) or "name" not in obj:
                return ("malformed", f"tool_call missing 'name': {obj}")
            return ("tool_call", obj)
        except json.JSONDecodeError as exc:
            return ("malformed", f"tool_call JSON parse failed: {exc}")

    m = _ANSWER_RE.search(raw)
    if m:
        return ("answer", m.group(1).strip())

    # No prefix - treat the whole thing as an answer (LLM forgot the prefix)
    return ("answer", raw.strip())


def run_agentic_chat(
    question: str,
    seed_context: str,
    conversation_summary: str,
    lm: Any,
) -> Dict[str, Any]:
    """Run the ReAct loop. Returns {answer, tool_calls, iterations}.

    tool_calls is a list of {name, args, result_summary} for transparency
    in the UI / for debugging.
    """
    # Optional Ollama-native function calling path (env-toggleable).
    # When OLLAMA_NATIVE_TOOLS=true and the active provider is ollama,
    # bypass DSPy + the prose parser and use Ollama's /api/chat with
    # tools[]. Smaller models (Mistral 7B v0.3) emit structured tool
    # calls reliably this way.
    try:
        from ai_agents.rag import agent_chat_native
        # Detect provider from the lm object's model string (DSPy LM
        # exposes .model like "ollama_chat/mistral:7b" / "groq/llama..." )
        model_str = getattr(lm, "model", "") or ""
        provider = "ollama" if model_str.startswith("ollama") else (
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
            )
    except Exception as exc:
        logger.warning("agent_chat.native_path_failed_falling_back: %s", exc)

    chain = _get_chain()
    catalogue = agent_tools.get_tool_descriptions()
    tool_history_lines: List[str] = []
    tool_calls: List[Dict[str, Any]] = []

    iteration = 0
    while iteration < MAX_ITERATIONS:
        iteration += 1
        # Cap tool history sent to the LLM at the last 3 entries to control
        # token usage — earlier entries are summarised as a count. Even with
        # max iterations of 5 this keeps the prompt size bounded.
        if not tool_history_lines:
            history_text = "(no tool calls yet)"
        elif len(tool_history_lines) <= 3:
            history_text = "\n".join(tool_history_lines)
        else:
            elided = len(tool_history_lines) - 3
            history_text = (
                f"[{elided} earlier tool call(s) elided]\n"
                + "\n".join(tool_history_lines[-3:])
            )

        try:
            with dspy.context(lm=lm):
                result = chain(
                    question=question,
                    seed_context=seed_context,
                    conversation_summary=conversation_summary,
                    tool_catalogue=catalogue,
                    tool_history=history_text,
                )
        except Exception as exc:
            logger.warning("agentic_chat.dspy_call_failed iter=%d: %s", iteration, exc)
            return {
                "answer": (
                    "I hit an internal error trying to formulate my response. "
                    f"({exc})"
                ),
                "tool_calls": tool_calls,
                "iterations": iteration,
                "error": str(exc),
            }

        raw = (getattr(result, "response", "") or "").strip()
        kind, payload = _parse_response(raw)

        logger.info(
            "agentic_chat.iter=%d kind=%s preview=%r",
            iteration, kind, raw[:200],
        )

        if kind == "answer":
            return {
                "answer": payload,
                "tool_calls": tool_calls,
                "iterations": iteration,
            }

        if kind == "malformed":
            # Surface the parsing problem to the LLM so it can recover
            tool_history_lines.append(
                f"[iter {iteration}] PARSE_ERROR: {payload}. "
                f"Remember: response must start with 'ANSWER:' or 'TOOL_CALL: {{json}}'."
            )
            continue

        # kind == "tool_call"
        tool_name = payload.get("name", "")
        tool_args = payload.get("args", {}) or {}
        if not isinstance(tool_args, dict):
            tool_args = {}

        tool_result = agent_tools.call_tool(tool_name, tool_args)

        # Compact the result for the next prompt. For search_alerts results
        # with many alerts, prefer the digest + a small sample of raw alerts
        # over the full list — the digest answers most "which/how many/list"
        # questions without burning tokens on 200 dicts.
        if isinstance(tool_result, dict) and tool_result.get("alerts"):
            compressed = {
                "total": tool_result.get("total"),
                "returned": tool_result.get("returned"),
                "digest": tool_result.get("digest"),
                # Keep first 10 raw alerts as concrete examples
                "sample_alerts": tool_result.get("alerts", [])[:10],
            }
            if "hint" in tool_result:
                compressed["hint"] = tool_result["hint"]
            result_json = json.dumps(compressed, default=str)
        else:
            result_json = json.dumps(tool_result, default=str)
        if len(result_json) > 8000:
            result_json = result_json[:8000] + "...(truncated)"

        # Build a short summary of the call for the UI
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

        # Cap the stored result so a 200-alert query doesn't bloat the
        # /chat response. Keep total/returned/digest/first 10 alerts.
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

        tool_calls.append({
            "name": tool_name,
            "args": tool_args,
            "result_summary": summary,
            "result": result_for_ui,
        })

        tool_history_lines.append(
            f"[iter {iteration}] CALLED {tool_name}({json.dumps(tool_args)}) "
            f"-> {result_json}"
        )

    # Hit max iterations without an ANSWER — make a best-effort final pass
    # asking explicitly for an answer using whatever was gathered.
    history_text = "\n".join(tool_history_lines)
    forced_summary = (
        conversation_summary
        + "\n\nIMPORTANT: You have used the maximum number of tool calls. "
        "You MUST now provide an ANSWER based on the data you've already gathered. "
        "Do not call any more tools."
    )
    try:
        with dspy.context(lm=lm):
            result = chain(
                question=question,
                seed_context=seed_context,
                conversation_summary=forced_summary,
                tool_catalogue=catalogue,
                tool_history=history_text,
            )
        raw = (getattr(result, "response", "") or "").strip()
        kind, payload = _parse_response(raw)
        if kind == "answer":
            answer = payload
        else:
            answer = raw or "I couldn't formulate a complete answer within the iteration limit."
    except Exception as exc:
        logger.warning("agentic_chat.final_pass_failed: %s", exc)
        answer = "I couldn't formulate a complete answer within the iteration limit."

    return {
        "answer": answer,
        "tool_calls": tool_calls,
        "iterations": iteration,
        "hit_iteration_limit": True,
    }
