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
    path_contains: Optional[str] = None,
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
    path_contains is a case-insensitive substring match against
    syscheck.path - use this for file integrity questions about a
    specific filename or directory.
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
        # Single case_insensitive wildcard - matches mixed-case stored
        # values like "SQLi" regardless of how the LLM phrased the query.
        # The match-query against full_log handles tokenized text fields.
        must.append({"bool": {"should": [
            {"match": {"full_log": kw}},
            {"wildcard": {"rule.description": {"value": f"*{kw}*", "case_insensitive": True}}},
            {"wildcard": {"data.alert.signature": {"value": f"*{kw}*", "case_insensitive": True}}},
        ], "minimum_should_match": 1}})

    if path_contains:
        # FIM file path filter. syscheck.path is keyword-mapped so we
        # use a case-insensitive wildcard. full_log also gets a match
        # query as a backup for events that don't have syscheck.path
        # populated.
        pkw = path_contains.strip()
        must.append({"bool": {"should": [
            {"wildcard": {"syscheck.path": {"value": f"*{pkw}*", "case_insensitive": True}}},
            {"match": {"full_log": pkw}},
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
    alerts = []
    for h in hits.get("hits", []):
        summary = _alert_to_summary(h.get("_source", {}))
        # Pass through OpenSearch metadata so the UI's document viewer
        # can fetch the original document on click.
        summary["_id"] = h.get("_id")
        summary["_index"] = h.get("_index")
        alerts.append(summary)
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
    # Auto-fallback: if no alerts matched, look in archives with the
    # same useful filters. Many SOC questions ("any X events?") are
    # ambiguous to small LLMs because they don't know which index a
    # given event type lives in. Hiding that distinction inside the
    # tool eliminates a whole class of wrong-tool failures.
    if result.get("total", 0) == 0:
        try:
            archive_query_parts = []
            if signature_contains:
                archive_query_parts.append(signature_contains)
            archive_result = search_archives(
                query=" ".join(archive_query_parts) if archive_query_parts else None,
                agent_name=agent_name,
                src_ip=src_ip,
                dst_ip=dst_ip,
                time_window=time_window,
                limit=min(limit, 30),
            )
            if archive_result.get("total", 0) > 0:
                logger.info(
                    "search_alerts.fallback_to_archives total=%d filters=%s",
                    archive_result.get("total", 0),
                    {
                        "signature_contains": signature_contains,
                        "agent_name": agent_name,
                        "src_ip": src_ip,
                        "time_window": time_window,
                    },
                )
                # Reshape archive result to look like an alerts result
                # so the LLM doesn't need to know it came from a
                # different index. Tag the source for transparency.
                events = archive_result.get("events", []) or archive_result.get("alerts", [])
                return {
                    "total": archive_result.get("total", 0),
                    "returned": archive_result.get("returned", len(events)),
                    "alerts": events,
                    "source": "archives",
                    "note": (
                        "No matching alerts (events that escalated to a Wazuh "
                        "rule). These results come from wazuh-archives-* — raw "
                        "events that did not trigger an alert."
                    ),
                }
        except Exception as exc:
            logger.warning("search_alerts.archive_fallback_failed: %s", exc)

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


# ─── Tool: get_incidents ──────────────────────────────────────────────


def get_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    time_window: str = "7d",
    limit: int = 20,
) -> Dict[str, Any]:
    """List incidents triaged by the orchestrator from the Postgres DB.

    The orchestrator is fired automatically on every level>=5 alert and
    runs log_analyzer (classify + MITRE) -> threat_intel (enrich) ->
    cve_scanner (NVD lookup) -> incident_responder (DB write) ->
    ansible_dispatch (playbook routing). Each run produces an Incident
    with severity, alert_type, mitre_techniques, analysis paragraph,
    recommended_action, and dispatch decision.

    Use this for questions like 'what incidents have we had today',
    'what did the system find about X', 'show high-severity incidents
    from this week', 'what playbooks were dispatched'.

    severity: 'low' / 'medium' / 'high' / 'critical' (None = all)
    status: 'open' / 'analyzing' / 'resolved' (None = all)
    time_window: OpenSearch-style date math ('7d', '24h', '30d')
    """
    from datetime import datetime, timedelta
    from ai_agents.database.db_manager import get_db
    from ai_agents.database.models import Incident

    # Parse time_window into a timedelta
    try:
        unit = time_window[-1].lower()
        n = int(time_window[:-1])
        delta = {"m": timedelta(minutes=n), "h": timedelta(hours=n),
                 "d": timedelta(days=n)}.get(unit, timedelta(days=7))
    except (ValueError, IndexError):
        delta = timedelta(days=7)
    cutoff = datetime.utcnow() - delta

    try:
        with get_db() as db:
            q = db.query(Incident).filter(Incident.created_at >= cutoff)
            if severity:
                q = q.filter(Incident.severity == severity.lower())
            if status:
                q = q.filter(Incident.status == status.lower())
            q = q.order_by(Incident.created_at.desc()).limit(min(limit, 100))
            rows = q.all()
            incidents = []
            for r in rows:
                incidents.append({
                    "id": r.id,
                    "wazuh_alert_id": r.wazuh_alert_id,
                    "rule_id": r.rule_id,
                    "rule_description": r.rule_description,
                    "severity": r.severity,
                    "status": r.status,
                    "source_ip": r.source_ip,
                    "dest_ip": r.dest_ip,
                    "mitre_techniques": r.mitre_techniques or [],
                    "analysis": (r.analysis or "")[:500],
                    "recommended_action": r.recommended_action,
                    "confidence_score": r.confidence_score,
                    "playbook_executed": r.playbook_executed,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                })
            return {"total": len(incidents), "incidents": incidents}
    except Exception as exc:
        logger.warning("agent_tools.get_incidents.failed: %s", exc)
        return {"total": 0, "incidents": [], "error": str(exc)}


# ─── Tool: get_incident_details ───────────────────────────────────────


def get_incident_details(incident_id: str) -> Dict[str, Any]:
    """Get the full record for one specific incident by ID.

    Returns the complete Incident dict including the raw alert_data,
    full analysis text, and playbook execution result. Use this when
    the LLM has an incident_id from get_incidents and needs to drill in.
    """
    from ai_agents.database.db_manager import get_db
    from ai_agents.database.models import Incident
    if not incident_id:
        return {"error": "incident_id required"}
    try:
        with get_db() as db:
            r = db.query(Incident).filter(Incident.id == incident_id).first()
            if not r:
                return {"error": f"no incident with id={incident_id}"}
            return {
                "id": r.id,
                "wazuh_alert_id": r.wazuh_alert_id,
                "rule_id": r.rule_id,
                "rule_description": r.rule_description,
                "severity": r.severity,
                "status": r.status,
                "source_ip": r.source_ip,
                "dest_ip": r.dest_ip,
                "mitre_techniques": r.mitre_techniques or [],
                "alert_data": r.alert_data or {},
                "analysis": r.analysis,
                "recommended_action": r.recommended_action,
                "confidence_score": r.confidence_score,
                "playbook_executed": r.playbook_executed,
                "playbook_result": r.playbook_result,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
            }
    except Exception as exc:
        logger.warning("agent_tools.get_incident_details.failed: %s", exc)
        return {"error": str(exc)}


# ─── Tool: search_archives ────────────────────────────────────────────


def search_archives(
    query: Optional[str] = None,
    agent_name: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    time_window: str = "24h",
    limit: int = 30,
) -> Dict[str, Any]:
    """Search the Wazuh archives index for raw events that did NOT
    escalate to alerts.

    The archives index (wazuh-archives-4.x-*) contains ALL events seen
    by the manager, including raw Suricata flows, pfSense syslog,
    decoded events that didn't match any rule. ~2M docs per day so
    filter aggressively. Use this for 'did we see traffic from IP X',
    'what flows touched port Y', 'is there evidence of activity that
    didn't fire an alert'.

    query: free-text against full_log (text field, supports tokenization)
    agent_name, src_ip, dst_ip: exact filters
    time_window: '30m', '24h', '7d' etc
    """
    body: Dict[str, Any] = {
        "size": min(max(int(limit), 1), 100),
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
            {"term": {"data.src_ip": src_ip}},
            {"term": {"data.srcip": src_ip}},
        ], "minimum_should_match": 1}})
    if dst_ip:
        must.append({"bool": {"should": [
            {"term": {"data.dest_ip": dst_ip}},
            {"term": {"data.dstip": dst_ip}},
        ], "minimum_should_match": 1}})
    if query:
        must.append({"match": {"full_log": query}})

    try:
        data = _get_client()._indexer_request(
            "POST", "/wazuh-archives-4.x-*/_search",
            json=body,
            headers={"Content-Type": "application/json"},
        )
    except Exception as exc:
        logger.warning("agent_tools.search_archives.failed: %s", exc)
        return {"total": 0, "events": [], "error": str(exc)}

    hits = data.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    events = []
    for h in hits.get("hits", []):
        src = h.get("_source", {})
        d = src.get("data", {}) or {}
        events.append({
            "timestamp": src.get("timestamp") or src.get("@timestamp"),
            "agent_name": (src.get("agent", {}) or {}).get("name"),
            "src_ip": d.get("src_ip") or d.get("srcip"),
            "dst_ip": d.get("dest_ip") or d.get("dstip"),
            "src_port": d.get("src_port"),
            "dest_port": d.get("dest_port"),
            "proto": d.get("proto"),
            "event_type": d.get("event_type"),
            "decoder": (src.get("decoder", {}) or {}).get("name"),
            "full_log_preview": (src.get("full_log") or "")[:200],
        })
    return {"total": total, "returned": len(events), "events": events}


# ─── Tool: agent_inventory ────────────────────────────────────────────


_INVENTORY_KINDS = {
    "packages", "services", "processes", "ports",
    "users", "groups", "networks", "interfaces",
    "hardware", "hotfixes", "protocols", "system",
    "browser-extensions",
}


def agent_inventory(
    agent_name: str,
    kind: str = "packages",
    contains: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Query agent system inventory (syscollector data).

    Wazuh agents periodically report their system state - installed
    packages, running processes, listening ports, users, groups,
    network interfaces, hardware, etc. Use this for 'what's installed
    on agent X', 'what processes are running', 'what ports are open'.

    agent_name: exact agent name (e.g. 'kali-agent-1', 'ubuntu-agent-2')
    kind: one of packages, services, processes, ports, users, groups,
          networks, interfaces, hardware, hotfixes, protocols, system,
          browser-extensions
    contains: optional case-insensitive substring filter against the
              kind-specific name field (package.name, service.name, etc).
    limit: max items to return (1-200)

    Note: despite the index naming pattern 'wazuh-states-inventory-
    {kind}-<suffix>', all agents' data lives in the same per-kind index
    in Wazuh 4.x; routing is by the agent.name field inside docs.
    """
    if kind not in _INVENTORY_KINDS:
        return {"error": f"invalid kind '{kind}'. Allowed: {sorted(_INVENTORY_KINDS)}"}
    if not agent_name:
        return {"error": "agent_name required"}

    body: Dict[str, Any] = {
        "size": min(max(int(limit), 1), 200),
        "query": {"bool": {"must": [
            {"match_phrase": {"agent.name": agent_name}},
        ]}},
    }
    if contains:
        # Match against the most likely name field for this kind. We
        # add a few fallbacks in a should clause to widen coverage.
        kw = contains.lower()
        body["query"]["bool"]["must"].append({"bool": {"should": [
            {"wildcard": {"package.name": f"*{kw}*"}},
            {"wildcard": {"service.name": f"*{kw}*"}},
            {"wildcard": {"process.name": f"*{kw}*"}},
            {"wildcard": {"user.name": f"*{kw}*"}},
            {"wildcard": {"group.name": f"*{kw}*"}},
            {"wildcard": {"interface.name": f"*{kw}*"}},
        ], "minimum_should_match": 1}})

    # Try the per-cluster index pattern (wazuh.manager suffix is a
    # cluster-name convention; doc routing is by agent.name field).
    index_pattern = f"/wazuh-states-inventory-{kind}-*/_search"
    try:
        data = _get_client()._indexer_request(
            "POST", index_pattern,
            json=body,
            headers={"Content-Type": "application/json"},
        )
    except Exception as exc:
        logger.warning("agent_tools.agent_inventory.failed: %s", exc)
        return {"total": 0, "items": [], "error": str(exc)}

    hits = data.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    items = []
    for h in hits.get("hits", []):
        src = h.get("_source", {})
        # Strip the wazuh metadata block - LLM doesn't need cluster info
        clean = {k: v for k, v in src.items() if k != "wazuh"}
        items.append(clean)
    return {"total": total, "returned": len(items), "kind": kind,
            "agent_name": agent_name, "items": items}


# ─── Registry ─────────────────────────────────────────────────────────


TOOLS: Dict[str, Any] = {
    "search_alerts": search_alerts,
    "count_alerts": count_alerts,
    "top_signatures": top_signatures,
    "list_agents": list_agents,
    "get_alert": get_alert,
    "get_incidents": get_incidents,
    "get_incident_details": get_incident_details,
    "search_archives": search_archives,
    "agent_inventory": agent_inventory,
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


_SEVERITY_NAME_TO_LEVEL = {
    # Wazuh rule.level scale 0-15. Common LLM strings -> rough numeric
    "info": 0, "informational": 0, "debug": 0,
    "low": 3,
    "medium": 5, "med": 5, "warning": 5, "warn": 5,
    "high": 7,
    "critical": 10, "crit": 10, "severe": 10,
    "fatal": 12,
}


def _coerce_int(value, field_name):
    """Try to coerce value to int, with helpful conversions for common
    LLM-isms like \"INFO\" -> 0, \"high\" -> 7, \"100\" -> 100.
    Returns the coerced int, or the original value if coercion fails
    (so the original tool call error surfaces unchanged).
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        s = value.strip()
        if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
            return int(s)
        mapped = _SEVERITY_NAME_TO_LEVEL.get(s.lower())
        if mapped is not None:
            return mapped
    return value


def _coerce_time_window(value):
    """LLMs sometimes send '7d-1h' or '7 days'. Normalize to OpenSearch
    date-math like '7d', '24h', '30m'. Falls back to original on no
    match so OpenSearch's own parser will surface a real error.
    """
    if not isinstance(value, str):
        return value
    import re as _re
    s = value.strip().lower().replace(" ", "")
    # Already valid: '24h', '7d', '30m', '30s'
    if _re.fullmatch(r"\d+[smhdwM]", s):
        return s
    # 'Nd-Xh' or 'Nd+Xh' — keep just the first chunk
    m = _re.match(r"(\d+[smhdwM])[-+]", s)
    if m:
        return m.group(1)
    # 'N days', 'N hours', etc.
    m = _re.fullmatch(r"(\d+)\s*(s|sec|second|seconds|m|min|minute|minutes|h|hour|hours|d|day|days|w|week|weeks)", s)
    if m:
        n, unit = m.group(1), m.group(2)
        unit_map = {
            "s": "s", "sec": "s", "second": "s", "seconds": "s",
            "m": "m", "min": "m", "minute": "m", "minutes": "m",
            "h": "h", "hour": "h", "hours": "h",
            "d": "d", "day": "d", "days": "d",
            "w": "w", "week": "w", "weeks": "w",
        }
        return f"{n}{unit_map.get(unit, 'd')}"
    return value


# Per-tool arg coercion rules. Each entry is a callable that takes
# the args dict and returns a (possibly modified) args dict, plus a
# list of (key, before, after) tuples for logging.
def _unwrap_schema_value(value):
    """Mistral 7B sometimes mirrors the JSON Schema as the argument
    value. Detect that pattern and extract the real value.

    Recognized shapes:
        {"type": "string", "value": "sql injection"}  -> "sql injection"
        {"type": "string"}                            -> None  (no real value)
        {"value": 100}                                -> 100
    """
    if not isinstance(value, dict):
        return value
    keys = set(value.keys())
    # Exact schema mirror with a value
    if "value" in keys and (keys <= {"type", "value", "description", "default", "enum"}):
        return value["value"]
    # Schema mirror without a value -> caller should drop the arg
    if keys <= {"type", "description", "default", "enum"}:
        return _SCHEMA_MIRROR_NO_VALUE
    return value


_SCHEMA_MIRROR_NO_VALUE = object()  # sentinel


# Real Wazuh rule.groups we ever see in our deployment. LLMs
# sometimes invent group names like "sql_injection" or "web_attack_sql"
# which don't match anything. We validate against this list and drop
# the rule_groups arg if no value is recognized.
_KNOWN_RULE_GROUPS = {
    "ossec", "syscheck", "syscheck_entry_modified", "syscheck_entry_added",
    "syscheck_entry_deleted", "syscheck_file", "rootcheck", "rootkit",
    "ids", "suricata", "scan", "attack", "trojan",
    "authentication_failed", "authentication_success", "ssh", "sshd",
    "web", "web_attack", "web_accesslog", "accesslog",
    "pam", "syslog", "sudo", "audit",
    "wazuh", "agent", "ossec_unauthorized",
}


def _parse_maybe_stringified_list(value):
    """LLMs sometimes wrap lists in strings: '["a", "b"]' or
    "['a', 'b']". Try to recover the actual list.
    """
    if isinstance(value, list):
        return value
    if not isinstance(value, str):
        return value
    s = value.strip()
    if not (s.startswith("[") and s.endswith("]")):
        return value
    import json as _j
    # Try strict JSON first
    try:
        return _j.loads(s)
    except Exception:
        pass
    # Try replacing single quotes with double quotes
    try:
        return _j.loads(s.replace("\'", "\""))
    except Exception:
        pass
    # Last resort: strip brackets and split
    inner = s[1:-1]
    parts = [p.strip().strip("\"\' ") for p in inner.split(",") if p.strip()]
    return parts if parts else value


def _coerce_search_alerts_args(args):
    coerced = []

    # Pass 1: unwrap schema-mirrored values
    for key in list(args.keys()):
        unwrapped = _unwrap_schema_value(args[key])
        if unwrapped is _SCHEMA_MIRROR_NO_VALUE:
            coerced.append((key, args[key], "<dropped:schema_mirror_no_value>"))
            del args[key]
        elif unwrapped != args[key]:
            coerced.append((key, args[key], unwrapped))
            args[key] = unwrapped

    # Pass 2: drop empty-string filters (LLM sent "" instead of omitting)
    for key in list(args.keys()):
        v = args[key]
        if isinstance(v, str) and v.strip() == "":
            coerced.append((key, v, "<dropped:empty_string>"))
            del args[key]

    # Pass 3: clean rule_groups - parse stringified lists, validate, drop if all invalid
    if "rule_groups" in args:
        before = args["rule_groups"]
        parsed = _parse_maybe_stringified_list(before)
        if isinstance(parsed, list):
            valid = [g.lower() for g in parsed if isinstance(g, str) and g.lower() in _KNOWN_RULE_GROUPS]
            if not valid:
                coerced.append(("rule_groups", before, "<dropped:no_valid_groups>"))
                del args["rule_groups"]
            elif valid != parsed:
                coerced.append(("rule_groups", before, valid))
                args["rule_groups"] = valid
        else:
            coerced.append(("rule_groups", before, "<dropped:not_a_list>"))
            del args["rule_groups"]
    if "min_level" in args:
        before = args["min_level"]
        after = _coerce_int(before, "min_level")
        if before != after:
            args["min_level"] = after
            coerced.append(("min_level", before, after))
    for key in ("limit", "dest_port"):
        if key in args:
            before = args[key]
            after = _coerce_int(before, key)
            if before != after:
                args[key] = after
                coerced.append((key, before, after))
    if "time_window" in args:
        before = args["time_window"]
        after = _coerce_time_window(before)
        if before != after:
            args["time_window"] = after
            coerced.append(("time_window", before, after))
    # Drop None-valued args entirely so the tool's defaults take effect
    # (LLMs sometimes send "src_ip": null which then falls into the
    #  query body and matches nothing)
    for k in list(args.keys()):
        if args[k] is None:
            del args[k]
            coerced.append((k, "null", "<dropped>"))
    return args, coerced


_PER_TOOL_COERCERS = {
    "search_alerts": _coerce_search_alerts_args,
    "count_alerts": _coerce_search_alerts_args,
    "top_signatures": _coerce_search_alerts_args,
    "search_archives": _coerce_search_alerts_args,
    "agent_inventory": _coerce_search_alerts_args,
    "get_incidents": _coerce_search_alerts_args,
}


def call_tool(name: str, args: Dict[str, Any]) -> Any:
    """Execute a tool by name with the given keyword arguments.

    Coerces common LLM-misformatted args (min_level=\"INFO\" -> 5,
    limit=\"100\" -> 100, time_window=\"7d-1h\" -> \"7d\", null
    values dropped) before invoking the underlying function.
    """
    fn = TOOLS.get(name)
    if fn is None:
        return {"error": f"unknown tool '{name}'. Available: {list(TOOLS.keys())}"}

    coercer = _PER_TOOL_COERCERS.get(name)
    if coercer is not None and isinstance(args, dict):
        args, coerced = coercer(dict(args))
        if coerced:
            logger.warning(
                "agent_tools.call_tool.coerced name=%s changes=%s",
                name, coerced,
            )

    try:
        return fn(**args)
    except TypeError as exc:
        return {"error": f"bad arguments to {name}: {exc}"}
    except Exception as exc:
        logger.warning("agent_tools.call_tool.failed name=%s: %s", name, exc)
        return {"error": f"{name} raised: {exc}"}
