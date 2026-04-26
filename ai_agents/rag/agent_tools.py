"""
Agentic retrieval tools for SENTINEL-AI Commander chatbot.

These functions are exposed to the LLM as callable tools. Each one:
  - Has a clear, focused purpose
  - Takes structured parameters
  - Returns small, JSON-serializable dicts/lists
  - Self-describes via its docstring

The LLM uses these in a ReAct loop: it sees an initial seed context
from the RAG retriever, decides what additional information it needs,
calls one or more tools, examines results, and formulates an answer.

All tools backed by the same OpenSearch indexer the RAG retriever uses.
"""
from __future__ import annotations

import inspect
import logging
from typing import Any, Dict, List, Optional

from ai_agents.tools.wazuh_client import WazuhClient

logger = logging.getLogger(__name__)


_client: Optional[WazuhClient] = None


def _get_client() -> WazuhClient:
    global _client
    if _client is None:
        _client = WazuhClient()
    return _client


def _alert_to_summary(src: Dict[str, Any]) -> Dict[str, Any]:
    """Compact representation of an alert for the LLM context."""
    rule = src.get("rule", {}) or {}
    agent = src.get("agent", {}) or {}
    data = src.get("data", {}) or {}
    alert = data.get("alert", {}) or {}
    src_ip = data.get("srcip") or data.get("src_ip")
    dst_ip = data.get("dstip") or data.get("dest_ip")
    src_port = data.get("src_port") or data.get("srcport")
    dest_port = data.get("dest_port") or data.get("dstport")
    return {
        "timestamp": src.get("timestamp") or src.get("@timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "rule_groups": rule.get("groups", []),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "proto": data.get("proto"),
        "suricata_signature": alert.get("signature"),
        "suricata_signature_id": alert.get("signature_id"),
        "suricata_category": alert.get("category"),
        "suricata_severity": alert.get("severity"),
        "mitre": rule.get("mitre", {}),
    }


# ─── Tool: search_alerts ──────────────────────────────────────────────


def search_alerts(
    agent_name: Optional[str] = None,
    signature_contains: Optional[str] = None,
    rule_groups: Optional[List[str]] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dest_port: Optional[int] = None,
    time_window: str = "7d",
    min_level: int = 0,
    limit: int = 100,
) -> Dict[str, Any]:
    """Search Wazuh alerts in the indexer with structured filters.

    All parameters are optional - pass only the ones that matter. Returns
    a dict with 'total' (total matching, may exceed limit) and 'alerts'
    (list of alert summaries with src/dst IPs, ports, signature, MITRE,
    timestamps).

    Filters combine with AND. signature_contains is a case-insensitive
    substring match against rule.description AND data.alert.signature.
    rule_groups matches if ANY of the given groups is on the alert.
    time_window is OpenSearch date math: '30m', '2h', '24h', '7d', '30d'.

    Use this as your primary tool for SOC questions about historical
    alerts. Call it repeatedly with refined filters as you drill in.
    """
    body: Dict[str, Any] = {
        "size": min(max(int(limit), 1), 200),
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": f"now-{time_window}"}}},
        ]}},
    }
    must = body["query"]["bool"]["must"]

    if agent_name:
        must.append({"match_phrase": {"agent.name": agent_name}})
    if src_ip:
        must.append({"bool": {"should": [
            {"term": {"data.srcip": src_ip}},
            {"term": {"data.src_ip": src_ip}},
        ], "minimum_should_match": 1}})
    if dst_ip:
        must.append({"bool": {"should": [
            {"term": {"data.dstip": dst_ip}},
            {"term": {"data.dest_ip": dst_ip}},
        ], "minimum_should_match": 1}})
    if dest_port is not None:
        port_str = str(dest_port)
        must.append({"bool": {"should": [
            {"term": {"data.dest_port": port_str}},
            {"term": {"data.dstport": port_str}},
        ], "minimum_should_match": 1}})
    if min_level > 0:
        must.append({"range": {"rule.level": {"gte": int(min_level)}}})
    if rule_groups:
        must.append({"bool": {"should": [
            {"match_phrase": {"rule.groups": g}} for g in rule_groups
        ], "minimum_should_match": 1}})
    if signature_contains:
        kw = signature_contains.strip()
        kw_lower = kw.lower()
        kw_upper = kw.upper()
        must.append({"bool": {"should": [
            {"match": {"full_log": kw}},
            {"wildcard": {"rule.description": f"*{kw_lower}*"}},
            {"wildcard": {"rule.description": f"*{kw_upper}*"}},
            {"wildcard": {"data.alert.signature": f"*{kw_lower}*"}},
            {"wildcard": {"data.alert.signature": f"*{kw_upper}*"}},
        ], "minimum_should_match": 1}})

    try:
        data = _get_client()._indexer_request(
            "POST", "/wazuh-alerts-4.x-*/_search",
            json=body,
            headers={"Content-Type": "application/json"},
        )
    except Exception as exc:
        logger.warning("agent_tools.search_alerts.failed: %s", exc)
        return {"total": 0, "returned": 0, "alerts": [], "error": str(exc)}

    hits = data.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    alerts = [_alert_to_summary(h.get("_source", {})) for h in hits.get("hits", [])]
    result = {"total": total, "returned": len(alerts), "alerts": alerts}
    # Aggregated digest — the LLM should prefer this over the raw alerts
    # list for "which ports / agents / signatures" questions. Keeps the
    # context fed to the answer-generation step small even for 200-alert
    # results.
    if alerts:
        from collections import Counter
        sig_counts = Counter(a.get("suricata_signature") or a.get("rule_description") or "?" for a in alerts)
        agent_counts = Counter(a.get("agent_name") for a in alerts if a.get("agent_name"))
        src_counts = Counter(a.get("src_ip") for a in alerts if a.get("src_ip"))
        dst_counts = Counter(a.get("dst_ip") for a in alerts if a.get("dst_ip"))
        dest_ports = sorted({int(a["dest_port"]) for a in alerts if a.get("dest_port") and str(a["dest_port"]).isdigit()})
        src_ports_sample = sorted({int(a["src_port"]) for a in alerts if a.get("src_port") and str(a["src_port"]).isdigit()})[:20]
        protos = Counter(a.get("proto") for a in alerts if a.get("proto"))
        timestamps = sorted([a.get("timestamp") for a in alerts if a.get("timestamp")])
        result["digest"] = {
            "signatures": [{"sig": s, "count": c} for s, c in sig_counts.most_common(15)],
            "agents":     [{"name": n, "count": c} for n, c in agent_counts.most_common(10)],
            "src_ips":    [{"ip": ip, "count": c} for ip, c in src_counts.most_common(10)],
            "dst_ips":    [{"ip": ip, "count": c} for ip, c in dst_counts.most_common(10)],
            "dest_ports": dest_ports,                           # full unique list — usually small
            "src_ports_sample": src_ports_sample,                # capped — usually huge ephemeral set
            "protocols":  [{"proto": p, "count": c} for p, c in protos.most_common(5)],
            "time_range": {"first": timestamps[0] if timestamps else None,
                           "last":  timestamps[-1] if timestamps else None},
        }
    # Help the LLM recover from empty results — be explicit about why
    # 0 hits happened and what to try next, instead of letting the LLM
    # blindly repeat the same query.
    if total == 0:
        hints = []
        if time_window in ("30m", "1h"):
            hints.append(
                f"time_window='{time_window}' may be too narrow — alerts "
                "can be hours old; try '24h' or '30d'"
            )
        if signature_contains:
            hints.append(
                f"signature_contains='{signature_contains}' may be too "
                "specific — try a broader term ('scan' instead of 'nmap'), "
                "or drop signature_contains and use rule_groups=['suricata','ids']"
            )
        if not hints:
            hints.append("filters may be too restrictive — relax one and retry")
        result["hint"] = "; ".join(hints)
    return result


# ─── Tool: count_alerts ───────────────────────────────────────────────


def count_alerts(
    agent_name: Optional[str] = None,
    signature_contains: Optional[str] = None,
    rule_groups: Optional[List[str]] = None,
    time_window: str = "7d",
    min_level: int = 0,
) -> Dict[str, Any]:
    """Count alerts matching filters without retrieving the documents.

    Cheap aggregation - use this when you only need a total ('how many
    port scans were there last week?') not the full alert list. Same
    filter semantics as search_alerts.
    """
    result = search_alerts(
        agent_name=agent_name,
        signature_contains=signature_contains,
        rule_groups=rule_groups,
        time_window=time_window,
        min_level=min_level,
        limit=1,
    )
    return {"total": result.get("total", 0)}


# ─── Tool: top_signatures ─────────────────────────────────────────────


def top_signatures(
    agent_name: Optional[str] = None,
    rule_groups: Optional[List[str]] = None,
    time_window: str = "7d",
    top_n: int = 10,
) -> Dict[str, Any]:
    """Aggregate alerts by signature and return the most frequent ones.

    Returns a list of {signature, count, agents}. Useful for questions
    like 'what are the most common Suricata alerts today' or 'which
    signatures fired most often on host X'.
    """
    body: Dict[str, Any] = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": f"now-{time_window}"}}},
        ]}},
        "aggs": {
            "by_sig": {
                "terms": {
                    "field": "data.alert.signature",
                    "size": min(max(int(top_n), 1), 50),
                    "order": {"_count": "desc"},
                },
                "aggs": {
                    "agents": {"terms": {"field": "agent.name", "size": 10}},
                },
            }
        },
    }
    must = body["query"]["bool"]["must"]
    if agent_name:
        must.append({"match_phrase": {"agent.name": agent_name}})
    if rule_groups:
        must.append({"bool": {"should": [
            {"match_phrase": {"rule.groups": g}} for g in rule_groups
        ], "minimum_should_match": 1}})

    try:
        data = _get_client()._indexer_request(
            "POST", "/wazuh-alerts-4.x-*/_search",
            json=body,
            headers={"Content-Type": "application/json"},
        )
    except Exception as exc:
        logger.warning("agent_tools.top_signatures.failed: %s", exc)
        return {"signatures": [], "error": str(exc)}

    buckets = data.get("aggregations", {}).get("by_sig", {}).get("buckets", [])
    out = []
    for b in buckets:
        agents = [a.get("key") for a in b.get("agents", {}).get("buckets", [])]
        out.append({
            "signature": b.get("key"),
            "count": b.get("doc_count", 0),
            "agents": agents,
        })
    return {"signatures": out}


# ─── Tool: list_agents ────────────────────────────────────────────────


def list_agents() -> Dict[str, Any]:
    """List enrolled Wazuh agents (id, name, ip, status, os).

    Returns ALL enrolled agents including disconnected ones, since the
    user typically wants to know everything that's been enrolled, not
    just what's currently up. Use this when the user references an
    agent by partial name, asks 'which agents do we have', or you need
    to verify an agent exists.
    """
    try:
        # No status filter — chatbot users want the full enrollment list.
        # Don't use 'select' parameter (Wazuh API rejects it as 400 Bad
        # Request on this endpoint). Just take the full agent dict and
        # extract the fields we need client-side.
        client = _get_client()
        data = client._manager_request(
            "GET", "/agents",
            params={"limit": 500},
        )
        agents = data.get("data", {}).get("affected_items", [])
    except Exception as exc:
        logger.warning("agent_tools.list_agents.failed: %s", exc)
        return {"agents": [], "error": str(exc)}
    out = []
    for a in agents:
        os_info = a.get("os", {}) or {}
        out.append({
            "id": a.get("id"),
            "name": a.get("name"),
            "ip": a.get("ip"),
            "status": a.get("status"),
            "os": os_info.get("name") or os_info.get("platform"),
        })
    return {"agents": out}


# ─── Tool: get_alert ──────────────────────────────────────────────────


def get_alert(doc_id: str, doc_index: str) -> Dict[str, Any]:
    """Fetch the FULL document for a single alert by its OpenSearch ID.

    Use this to drill into a specific alert when summary fields aren't
    enough - inspect raw full_log, examine all decoded fields, look at
    flow stats. Pass doc_id and doc_index from a prior search_alerts
    result.
    """
    if not doc_id or not doc_index:
        return {"error": "doc_id and doc_index are required"}
    try:
        data = _get_client()._indexer_request(
            "GET", f"/{doc_index}/_doc/{doc_id}",
        )
    except Exception as exc:
        logger.warning("agent_tools.get_alert.failed: %s", exc)
        return {"error": str(exc)}
    return data.get("_source", {})


# ─── Registry ─────────────────────────────────────────────────────────


TOOLS: Dict[str, Any] = {
    "search_alerts": search_alerts,
    "count_alerts": count_alerts,
    "top_signatures": top_signatures,
    "list_agents": list_agents,
    "get_alert": get_alert,
}


def get_tool_descriptions() -> str:
    """Build a textual catalogue of available tools for the LLM prompt."""
    lines = []
    for name, fn in TOOLS.items():
        doc = (fn.__doc__ or "").strip()
        first_para = doc.split("\n\n")[0].replace("\n", " ").strip()
        sig = inspect.signature(fn)
        params = []
        for pname, p in sig.parameters.items():
            if p.default is inspect.Parameter.empty:
                params.append(pname)
            else:
                params.append(f"{pname}={p.default!r}")
        lines.append(f"- {name}({', '.join(params)}): {first_para}")
    return "\n".join(lines)


def call_tool(name: str, args: Dict[str, Any]) -> Any:
    """Execute a tool by name with the given keyword arguments."""
    fn = TOOLS.get(name)
    if fn is None:
        return {"error": f"unknown tool '{name}'. Available: {list(TOOLS.keys())}"}
    try:
        return fn(**args)
    except TypeError as exc:
        return {"error": f"bad arguments to {name}: {exc}"}
    except Exception as exc:
        logger.warning("agent_tools.call_tool.failed name=%s: %s", name, exc)
        return {"error": f"{name} raised: {exc}"}
