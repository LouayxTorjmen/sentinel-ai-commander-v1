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
        **({"src_ip": src_ip} if src_ip else {}),
        **({"dst_ip": dst_ip} if dst_ip else {}),
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
    limit: int = 200,
) -> Dict[str, Any]:
    """NOTE: use top_signatures for unique/most-common alert type questions. search_alerts is for specific recent events with timestamps and details.
    Search Wazuh alerts in the indexer with structured filters.

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
        "size": min(max(int(limit) * 5, 500), 1000),  # fetch more for dedup, return limit unique groups
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": f"now-{time_window}"}}},
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
    # Deduplicate by (rule_description, agent_name, src_ip) — Option B
    # Keep the most recent example of each unique combination, add occurrences count
    seen: dict = {}
    for a in alerts:
        key = (
            a.get("rule_description") or a.get("suricata_signature") or "",
            a.get("agent_name") or "",
            a.get("src_ip") or "",
        )
        if key not in seen:
            seen[key] = dict(a)
            seen[key]["occurrences"] = 1
        else:
            seen[key]["occurrences"] += 1
            # Keep the most recent timestamp
            if a.get("timestamp", "") > seen[key].get("timestamp", ""):
                ts = a.get("timestamp")
                id_ = a.get("_id")
                idx_ = a.get("_index")
                seen[key].update({"timestamp": ts, "_id": id_, "_index": idx_})
    # Filter out SCA/compliance noise from deduped results
    _noise_rules = {"594", "750", "19005", "19006", "19007", "19008",
                    "19009", "19010", "19011", "19012", "19013", "19014"}
    deduped = [
        a for a in sorted(seen.values(), key=lambda x: x.get("timestamp", ""), reverse=True)
        if str(a.get("rule_id", "")) not in _noise_rules
    ]
    # If we got fewer unique types than expected, enrich with top_signatures aggregation
    # This ensures AD-CS, Kerberoast, and other low-frequency but high-value alerts appear
    if len(deduped) < 20:
        try:
            agg_body = {
                "size": 0,
                "query": body["query"],
                "aggs": {
                    "by_rule": {
                        "terms": {"field": "rule.description", "size": 50, "order": {"_count": "desc"}},
                        "aggs": {"agents": {"terms": {"field": "agent.name", "size": 5}}}
                    }
                }
            }
            agg_data = _get_client()._indexer_request(
                "POST", "/wazuh-alerts-4.x-*/_search",
                json=agg_body, headers={"Content-Type": "application/json"},
            )
            agg_buckets = agg_data.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
            # Build a set of existing rule descriptions already in deduped
            existing = {a.get("rule_description", "") for a in deduped}
            _agg_skip = {"CIS Microsoft", "Score less than", "CVE-", "affects Microsoft"}
            for b in agg_buckets:
                sig = b.get("key", "")
                if sig and sig not in existing and sig not in _noise_rules and not any(s in sig for s in _agg_skip):
                    agents = [a.get("key") for a in b.get("agents", {}).get("buckets", [])]
                    deduped.append({
                        "rule_description": sig,
                        "occurrences": b.get("doc_count", 0),
                        "agent_name": agents[0] if agents else "",
                        "timestamp": "",
                        "_id": "",
                        "_index": "",
                        "_from_aggregation": True,
                    })
                    existing.add(sig)
        except Exception:
            pass
    rows = ["| Occurrences | Timestamp (UTC) | Rule | Description | Agent |", "|---|---|---|---|---|"]
    for a in deduped[:20]:
        occ = a.get("occurrences", 1)
        ts = (a.get("timestamp") or "—")[:19].replace("T"," ")
        rule = str(a.get("rule_id") or "—")
        desc = (a.get("rule_description") or a.get("suricata_signature") or "—")[:55]
        ag = a.get("agent_name") or "—"
        rows.append(f"| {occ} | {ts} | {rule} | {desc} | {ag} |")
    fmt = f"**{total:,} total** → **{len(deduped)} unique** alert types:\n\n" + "\n".join(rows)
    result = {"total": total, "returned": len(deduped), "unique": len(deduped), "alerts": deduped, "formatted": fmt}
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
    if result.get("total", 0) == 0 and min_level <= 5:
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
    total = result.get("total", 0)
    return {"total": total, "formatted": f"{total:,} alerts matched your query."}


# ─── Tool: top_signatures ─────────────────────────────────────────────


def top_signatures(
    agent_name: Optional[str] = None,
    rule_groups: Optional[List[str]] = None,
    time_window: str = "7d",
    top_n: int = 10,
    min_level: int = 0,
) -> Dict[str, Any]:
    """Aggregate alerts by signature and return the most frequent ones.

    Returns a list of {signature, count, agents}. Useful for questions
    like 'what are the most common Suricata alerts today' or 'which
    signatures fired most often on host X'.
    """
    body: Dict[str, Any] = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": f"now-{time_window}"}}},
        ]}},
        "aggs": {
            "by_sig": {
                "terms": {
                    "field": "data.alert.signature",
                    "size": min(max(int(top_n), 1), 50),
                    "order": {"_count": "desc"},
                    "missing": "__none__",
                },
                "aggs": {
                    "agents": {"terms": {"field": "agent.name", "size": 10}},
                },
            },
            "by_rule": {
                "terms": {
                    "field": "rule.description",
                    "size": min(max(int(top_n), 1), 50),
                    "order": {"_count": "desc"},
                },
                "aggs": {
                    "agents": {"terms": {"field": "agent.name", "size": 10}},
                },
            },
        },
    }
    must = body["query"]["bool"]["must"]
    if agent_name:
        must.append({"match_phrase": {"agent.name": agent_name}})
    if rule_groups:
        must.append({"bool": {"should": [
            {"match_phrase": {"rule.groups": g}} for g in rule_groups
        ], "minimum_should_match": 1}})
    if min_level > 0:
        must.append({"range": {"rule.level": {"gte": int(min_level)}}})

    try:
        data = _get_client()._indexer_request(
            "POST", "/wazuh-alerts-4.x-*/_search",
            json=body,
            headers={"Content-Type": "application/json"},
        )
    except Exception as exc:
        logger.warning("agent_tools.top_signatures.failed: %s", exc)
        return {"signatures": [], "error": str(exc)}

    aggs = data.get("aggregations", {})
    # Use Suricata signature if available, else fall back to rule.description
    buckets = aggs.get("by_sig", {}).get("buckets", [])
    buckets = [b for b in buckets if b.get("key") != "__none__"]
    if not buckets:
        buckets = aggs.get("by_rule", {}).get("buckets", [])
    out = []
    for b in buckets:
        agents = [a.get("key") for a in b.get("agents", {}).get("buckets", [])]
        out.append({
            "signature": b.get("key"),
            "count": b.get("doc_count", 0),
            "agents": agents,
        })
    # Pre-formatted output — LLM includes verbatim
    if out:
        rows = ["| Count | Alert Type | Agents |", "|---|---|---|"]
        for s in out:
            agents_str = ", ".join(s.get("agents", [])) or "all"
            sig = (s.get("signature") or "").replace("|", "\\|")
            rows.append(f"| {s['count']} | {sig} | {agents_str} |")
        formatted = "\n".join(rows)
    else:
        formatted = "No signatures found."
    return {"signatures": out, "formatted": formatted}


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
    active       = [a for a in out if a["status"] == "active"]
    disconnected = [a for a in out if a["status"] != "active"]
    # Summary string first so the model reads it before the list
    summary = f"{len(active)} active, {len(disconnected)} disconnected (total {len(out)})"
    rows = ["| Status | Name | IP | OS |", "|---|---|---|---|"]
    for a in out:
        icon = "🟢" if a.get("status") == "active" else "🔴"
        os_str = (a.get("os") or "—")[:25]
        rows.append(f"| {icon} {a['status']} | {a['name']} | {a.get('ip','—')} | {os_str} |")
    formatted = f"**{summary}**\n\n" + "\n".join(rows)
    return {
        "ANSWER":             summary,
        "active_count":       len(active),
        "disconnected_count": len(disconnected),
        "total":              len(out),
        "active_agents":      ", ".join(a["name"] for a in active),
        "disconnected_agents":", ".join(a["name"] for a in disconnected),
        "agent_details":      out,
        "formatted":          formatted,
    }


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
    src = data.get("_source", {})
    rule  = src.get("rule", {})
    agent = src.get("agent", {})
    ts    = (src.get("@timestamp") or src.get("timestamp","—"))[:19].replace("T"," ")
    src["formatted"] = (
        f"**Alert: {rule.get('description','—')}**\n"
        f"- **Rule:** {rule.get('id','—')} (Level {rule.get('level','—')})\n"
        f"- **Agent:** {agent.get('name','—')}\n"
        f"- **Time:** {ts} UTC\n"
        f"- **Groups:** {', '.join(rule.get('groups',[]) or [])}\n"
        f"- **Full log:** {(src.get('full_log') or '—')[:200]}"
    )
    return src


# ─── Tool: get_incidents ──────────────────────────────────────────────


def get_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    time_window: str = "7d",
    limit: int = 20,
) -> Dict[str, Any]:
    """List incidents and playbook executions from the Postgres DB.
    CORRECT TOOL for: 'what playbooks were executed today?', 'what incidents happened?',
    'did SENTINEL respond to any attacks?', 'what was blocked automatically?',
    'show automated responses', 'what playbooks ran this week?'.
    Returns: playbook_executed, rule_id, severity, source_ip, timestamps for each incident.
    severity: 'low'/'medium'/'high'/'critical' (None=all)
    status: 'open'/'analyzing'/'resolved'/'responding' (None=all)
    time_window: '24h', '7d', '30d'
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
            # Noise rule IDs — SCA compliance checks and registry FIM checksums
            NOISE_RULE_IDS = [
                594, 750,          # Windows registry FIM checksums
                19005, 19006, 19007, 19008, 19009,
                19010, 19011, 19012, 19013, 19014,  # SCA check results
            ]
            q = db.query(Incident).filter(Incident.created_at >= cutoff)
            if severity:
                q = q.filter(Incident.severity == severity.lower())
            if status:
                q = q.filter(Incident.status == status.lower())
            # Exclude SCA/compliance/registry noise
            q = q.filter(~Incident.rule_id.in_(NOISE_RULE_IDS))
            # Also exclude by description patterns
            noise_patterns = [
                "CIS Microsoft",
                "Score less than",
                "Registry Key Integrity Checksum",
                "Registry Value Integrity Checksum",
                "SCA summary",
            ]
            for pattern in noise_patterns:
                q = q.filter(~Incident.rule_description.contains(pattern))
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
            summary = f"{len(incidents)} incidents found"
        if incidents:
            playbooks = list({i["recommended_action"] for i in incidents if i.get("recommended_action")})
            summary += f". Playbooks: {', '.join(playbooks)}"
        rows = ["| Time (UTC) | Playbook | Host | Source IP | Severity |", "|---|---|---|---|---|"]
        for inc in incidents:
            ts = (inc.get("created_at") or "—")[:19].replace("T"," ")
            pb = inc.get("playbook_executed") or inc.get("recommended_action") or "—"
            host = (inc.get("alert_data") or {}).get("agent",{}).get("name","—") if isinstance(inc.get("alert_data"),dict) else "—"
            sip = inc.get("source_ip") or "—"
            sev = inc.get("severity") or "—"
            rows.append(f"| {ts} | {pb} | {host} | {sip} | {sev} |")
        formatted = f"**{summary}**\n\n" + "\n".join(rows) if incidents else f"No incidents found."
        return {"total": len(incidents), "summary": summary, "incidents": incidents, "formatted": formatted}
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
                if not r:
                    return {"error": f"no incident with id={incident_id}"}
            result = {
                "id": str(r.id),
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
            mitre_str = ", ".join(r.mitre_techniques or []) or "Not mapped"
            analysis_str = (r.analysis or "").strip()
            if not analysis_str:
                analysis_str = f"Phase 2 auto-dispatch: {r.recommended_action} triggered by rule {r.rule_id}"
            result["formatted"] = (
                f"**Incident {str(r.id)[:8]}** — {r.severity} / {r.status}\n"
                f"- **Rule:** {r.rule_id} — {r.rule_description}\n"
                f"- **Source IP:** {r.source_ip or '—'}\n"
                f"- **MITRE:** {mitre_str}\n"
                f"- **Playbook executed:** {r.playbook_executed or '—'}\n"
                f"- **Analysis:** {analysis_str[:400]}\n"
                f"- **Created:** {r.created_at.isoformat()[:19].replace('T',' ') if r.created_at else '—'} UTC"
            )
            return result
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
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": f"now-{time_window}"}}},
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
            "_id":        h.get("_id", ""),
            "_index":     h.get("_index", ""),
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
    rows = ["| Time (UTC) | Agent | Src IP | Log |", "|---|---|---|---|"]
    for e in events:
        ts = (e.get("timestamp") or "—")[:19].replace("T"," ")
        ag = e.get("agent_name") or "—"
        sip = e.get("src_ip") or "—"
        log = (e.get("full_log") or e.get("message") or "—")[:60]
        rows.append(f"| {ts} | {ag} | {sip} | {log} |")
    fmt = f"**{total:,} archive events** (showing {len(events)}):\n\n" + "\n".join(rows) if events else "No archive events found."
    return {"total": total, "returned": len(events), "events": events, "formatted": fmt}


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
    if kind == "ports":
        rows = ["| Protocol | Local Port | State |", "|---|---|---|"]
        for it in items:
            proto = it.get("protocol","—")
            port = ((it.get("local") or {}).get("port") or "—")
            state = it.get("state","—")
            rows.append(f"| {proto} | {port} | {state} |")
    elif kind == "processes":
        rows = ["| PID | Name | State |", "|---|---|---|"]
        for it in items:
            rows.append(f"| {it.get('pid','—')} | {(it.get('name') or '—')[:40]} | {it.get('state','—')} |")
    elif kind == "packages":
        rows = ["| Package | Version | Arch |", "|---|---|---|"]
        for it in items:
            rows.append(f"| {(it.get('name') or '—')[:40]} | {(it.get('version') or '—')[:20]} | {it.get('architecture','—')} |")
    else:
        rows = [f"| {str(it)[:80]} |" for it in items[:10]]
    fmt = f"**{agent_name} — {kind}** ({total:,} total, showing {len(items)}):\n\n" + "\n".join(rows)
    return {"total": total, "returned": len(items), "kind": kind,
            "agent_name": agent_name, "items": items, "formatted": fmt}


# ─── Registry ─────────────────────────────────────────────────────────



# =============================================================================
# ADDITIONS TO ai_agents/rag/agent_tools.py
# =============================================================================
# Paste these functions into agent_tools.py BEFORE the TOOLS = {...} dict.
# Then add their entries to TOOLS and _PER_TOOL_COERCERS as shown at the bottom.
#
# These 7 tools fill the gaps identified in the architecture audit:
#   get_agent_details          — agent health/OS/version/last seen
#   get_agent_vulnerabilities  — CVEs from Wazuh's vuln module (replaces CVEScanner)
#   get_wazuh_rule             — rule definition lookup ("why did rule X fire?")
#   get_fim_events             — dedicated FIM query with path filter
#   execute_playbook           — run Ansible playbooks on command (2-phase confirmation)
#   get_active_blocks          — what is currently blocked, why was X banned
#   get_sca_results            — CIS benchmark / SCA compliance per agent
# =============================================================================

import time as _time   # already imported in agent_tools.py as time; alias avoids collision


# ── Internal helpers ──────────────────────────────────────────────────────────

def _agent_id_from_name(agent_name: str) -> Optional[str]:
    """Resolve a Wazuh agent name to its numeric ID.

    Returns None if the agent is not found.
    Used by tools that need the agent ID for Manager API calls
    (vulnerability module, SCA) rather than the name.
    """
    try:
        client = _get_client()
        data = client._manager_request(
            "GET", "/agents",
            params={"search": agent_name, "limit": 10},
        )
        agents = data.get("data", {}).get("affected_items", [])
        # Prefer exact name match over search ranking
        exact = next((a for a in agents if a.get("name") == agent_name), None)
        if exact:
            return str(exact["id"])
        return str(agents[0]["id"]) if agents else None
    except Exception:
        return None


# ─── Tool: get_agent_details ─────────────────────────────────────────


def get_agent_details(agent_name: str) -> Dict[str, Any]:
    """Get full status and metadata for a specific Wazuh agent.

    Returns OS, version, connection status, last keepalive, IP, and group
    membership. Use for 'show me the status of X', 'is agent Y online',
    'what OS is srv-sql running'.

    agent_name: exact agent name (e.g. 'srv-web', 'srv-ad-dns', 'srv-sql').
    """
    if not agent_name:
        return {"error": "agent_name required"}
    try:
        client = _get_client()
        data = client._manager_request(
            "GET", "/agents",
            params={"search": agent_name, "limit": 10},
        )
        agents = data.get("data", {}).get("affected_items", [])
        agent = next((a for a in agents if a.get("name") == agent_name), None)
        if agent is None:
            # Partial-name fallback: take closest match
            agent = agents[0] if agents else None
        if agent is None:
            return {"error": f"Agent '{agent_name}' not found. Use list_agents() to see all enrolled agents."}

        os_info = agent.get("os", {}) or {}
        os_info2 = agent.get("os", {}) or {}
        details = {
            "id":             agent.get("id"),
            "name":           agent.get("name"),
            "ip":             agent.get("ip"),
            "status":         agent.get("status"),
            "version":        agent.get("version"),
            "os_name":        os_info2.get("name"),
            "os_platform":    os_info2.get("platform"),
            "os_version":     os_info2.get("version"),
            "os_arch":        os_info2.get("arch"),
            "last_keepalive": agent.get("lastKeepAlive"),
            "date_enrolled":  agent.get("dateAdd"),
            "group":          agent.get("group") or [],
            "manager":        agent.get("manager"),
            "node_name":      agent.get("node_name"),
        }
        icon = "🟢" if details["status"] == "active" else "🔴"
        details["formatted"] = (
            f"**{icon} {details['name']}** — {details['status']}\n"
            f"- **IP:** {details['ip']}\n"
            f"- **OS:** {details['os_name']} {details['os_version']} ({details['os_arch']})\n"
            f"- **Wazuh version:** {details['version']}\n"
            f"- **Last seen:** {(details['last_keepalive'] or '—')[:19].replace('T',' ')} UTC\n"
            f"- **Enrolled:** {(details['date_enrolled'] or '—')[:10]}\n"
            f"- **Manager:** {details['manager']}"
        )
        return details
    except Exception as exc:
        logger.warning("agent_tools.get_agent_details.failed: %s", exc)
        return {"error": str(exc)}


# ─── Tool: get_agent_vulnerabilities ─────────────────────────────────


def get_agent_vulnerabilities(
    agent_name: str,
    severity: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    """Get CVE vulnerabilities detected by Wazuh on a specific agent.

    Queries Wazuh's built-in vulnerability module which scans installed
    packages against the NVD. More reliable than keyword NVD searches.
    Use for 'what CVEs does srv-sql have?', 'are there any critical vulns
    on agent X?', 'what needs patching?'.

    agent_name: exact agent name.
    severity: filter by CVSS severity ('critical', 'high', 'medium', 'low').
              Omit to return all severities.
    limit: max results (1-100). Default 20.
    """
    if not agent_name:
        return {"error": "agent_name required"}

    agent_id = _agent_id_from_name(agent_name)
    if agent_id is None:
        return {"error": f"Agent '{agent_name}' not found"}

    try:
        # Query OpenSearch vulnerability index directly (Wazuh 4.8+ stores vulns here)
        client = _get_client()
        must = [{"match": {"agent.name": agent_name}}]
        _valid_severities = {"critical", "high", "medium", "low"}
        if severity and severity.lower() in _valid_severities:
            must.append({"match": {"vulnerability.severity": severity.capitalize()}})
        query = {"bool": {"must": must}}

        # Step 1: Get top unique packages via aggregation
        agg_body = {
            "size": 0,
            "query": query,
            "aggs": {
                "by_pkg": {
                    "terms": {"field": "package.name", "size": min(max(int(limit), 10), 50)},
                    "aggs": {
                        "worst_sev": {"terms": {"field": "vulnerability.severity", "size": 5}},
                        "max_cvss": {"max": {"field": "vulnerability.score.base"}},
                        "sample_cves": {"top_hits": {"size": 50, "_source": [
                            "vulnerability.id", "vulnerability.severity",
                            "vulnerability.score.base", "vulnerability.description",
                            "package.name", "package.version"
                        ]}}
                    }
                },
                "total_pkgs": {"cardinality": {"field": "package.name"}}
            }
        }
        agg_data = client._indexer_request(
            "POST", "/wazuh-states-vulnerabilities-*/_search",
            json=agg_body, headers={"Content-Type": "application/json"},
        )
        total = agg_data.get("hits", {}).get("total", {}).get("value", 0)
        pkg_buckets = agg_data.get("aggregations", {}).get("by_pkg", {}).get("buckets", [])

        vulns = []
        for b in pkg_buckets:
            for h in b.get("sample_cves", {}).get("hits", {}).get("hits", []):
                src = h.get("_source", {})
                vuln = src.get("vulnerability", {})
                pkg = src.get("package", {})
                score = vuln.get("score", {})
                cvss_raw = score.get("base") if isinstance(score, dict) else score
                cvss = cvss_raw if (cvss_raw is not None and cvss_raw > 0) else None
                _raw_desc = vuln.get("description") or ""
                _prefix = "In the Linux kernel, the following vulnerability has been resolved:"
                _raw_stripped = _raw_desc.lstrip("(").strip()
                if _raw_stripped.startswith(_prefix):
                    _title = _raw_stripped[len(_prefix):].strip().rstrip(")")
                else:
                    _title = _raw_desc
                vulns.append({
                    "cve_id":     vuln.get("id"),
                    "severity":   vuln.get("severity") or "Unrated",
                    "cvss_score": cvss,
                    "package":    pkg.get("name") or b.get("key"),
                    "version":    pkg.get("version"),
                    "title":      _title,
                })
        from collections import Counter
        sev_counts = Counter(v["severity"] for v in vulns if v.get("severity") and v["severity"] not in ("-","None","none","N/A",""))
        # Group by package+version
        from collections import defaultdict
        by_pkg = defaultdict(list)
        for v in vulns:
            pkg_key = f"{v['package'] or '?'}||{v['version'] or ''}"
            by_pkg[pkg_key].append(v)

        # Build packages summary — sorted by worst CVSS
        _sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        packages_summary = []
        for pkg_key, pkg_vulns in by_pkg.items():
            pkg_name, pkg_ver = pkg_key.split("||", 1)
            worst_sev = max(pkg_vulns, key=lambda v: _sev_order.get(v.get("severity","Low"),0))
            max_cvss = max((v.get("cvss_score") or 0) for v in pkg_vulns)
            packages_summary.append({
                "package":         pkg_name,
                "version":         pkg_ver,
                "cve_count":       len(pkg_vulns),
                "worst_severity":  worst_sev.get("severity","—"),
                "max_cvss":        max_cvss,
                "cves":            pkg_vulns,
            })
        packages_summary.sort(key=lambda p: (_sev_order.get(p["worst_severity"],0), p["max_cvss"]), reverse=True)

        # Formatted: unique packages table (top 20)
        sev_str = " | ".join(f"{k}: {n}" for k, n in sev_counts.most_common())
        rows = [
            f"**{agent_name}** — {total:,} vulnerabilities across {len(packages_summary)} unique packages",
            f"Severity breakdown: {sev_str or 'none'}\n",
            "| Package | Version | CVEs | Severity | Max CVSS |",
            "|---|---|---|---|---|"
        ]
        for p in packages_summary[:20]:
            cvss_str = str(p['max_cvss']) if p.get('max_cvss') and p['max_cvss'] > 0 else 'N/A'
            rows.append(f"| {p['package']} | {p['version']} | {p['cve_count']} | {p.get('worst_severity','?')} | {cvss_str} |")
        fmt = "\n".join(rows)
        # Write-through cache to cve_records (upsert — skip if already exists)
        try:
            from ai_agents.database.db_manager import get_db
            from ai_agents.database.models import CVERecord
            seen_ids = set()
            with get_db() as db:
                for v in vulns:
                    cid = v.get("cve_id")
                    if not cid or cid in seen_ids: continue
                    seen_ids.add(cid)
                    existing = db.query(CVERecord).filter(CVERecord.cve_id == cid).first()
                    if existing:
                        # Update description/score if we have better data
                        if v.get("title") and not existing.description:
                            existing.description = v["title"]
                        if v.get("cvss_score") and v["cvss_score"] > 0:
                            existing.cvss_score = v["cvss_score"]
                        if v.get("severity") and v["severity"] != "Unrated":
                            existing.severity = v["severity"]
                    else:
                        db.add(CVERecord(
                            cve_id            = cid,
                            description       = v.get("title") or "",
                            cvss_score        = v.get("cvss_score") if v.get("cvss_score") and v["cvss_score"] > 0 else None,
                            severity          = v.get("severity") or "Unrated",
                            affected_products = [{"package": v.get("package"), "version": v.get("version")}],
                        ))
                db.commit()
        except Exception as _ce:
            logger.debug("cve_cache_write_failed: %s", _ce)

        return {
            "agent_name":       agent_name,
            "total":            total,
            "returned":         len(vulns),
            "severity_summary": dict(sev_counts),
            "vulnerabilities":  vulns,
            "packages":         packages_summary,
            "formatted":        fmt,
        }
    except Exception as exc:
        logger.warning("agent_tools.get_agent_vulnerabilities.failed: %s", exc)
        return {"error": str(exc)}
        return {"error": str(exc)}


# ─── Tool: get_wazuh_rule ─────────────────────────────────────────────


def get_wazuh_rule(rule_id: str) -> Dict[str, Any]:
    """Look up a Wazuh rule definition by its ID.

    Returns the rule's description, level, groups, MITRE mappings,
    compliance standards (PCI-DSS, GDPR, HIPAA), and the file it lives in.
    Use for 'why did rule X fire?', 'what does rule 100601 detect?',
    'what MITRE technique is rule 550?'.

    rule_id: Wazuh rule ID as a string (e.g. '100601', '550', '5712').
    """
    if not rule_id:
        return {"error": "rule_id required"}
    try:
        client = _get_client()
        data = client._manager_request(
            "GET", "/rules",
            params={"rule_ids": str(rule_id)},
        )
        items = data.get("data", {}).get("affected_items", [])
        if not items:
            return {"error": f"Rule {rule_id} not found in Wazuh ruleset"}

        rule = items[0]
        mitre = rule.get("mitre") or []
        # mitre is a flat list of technique IDs e.g. ["T1649"]
        if isinstance(mitre, dict):
            techniques = ", ".join(mitre.get("technique", []))
            tactics = ", ".join(mitre.get("tactic", []))
        else:
            techniques = ", ".join(mitre) if mitre else "—"
            tactics = "—"
        result = {
            "id":          rule.get("id"),
            "description": rule.get("description"),
            "level":       rule.get("level"),
            "groups":      rule.get("groups", []),
            "mitre":       mitre,
            "filename":    rule.get("filename"),
            "gdpr":        rule.get("gdpr", []),
            "pci_dss":     rule.get("pci_dss", []),
            "hipaa":       rule.get("hipaa", []),
            "tsc":         rule.get("tsc", []),
            "nist_800_53": rule.get("nist_800_53", []),
        }
        result["formatted"] = (
            f"**Rule {result['id']}** — Level {result['level']}\n"
            f"**Description:** {result['description']}\n"
            f"**Groups:** {', '.join(result['groups']) or '—'}\n"
            f"**MITRE:** {techniques or '—'}\n"
            f"**File:** {result['filename']}"
        )
        return result
    except Exception as exc:
        logger.warning("agent_tools.get_wazuh_rule.failed: %s", exc)
        return {"error": str(exc)}


# ─── Tool: get_fim_events ─────────────────────────────────────────────


def get_fim_events(
    agent_name: Optional[str] = None,
    path_contains: Optional[str] = None,
    time_window: str = "7d",
    limit: int = 30,
) -> Dict[str, Any]:
    """Search for File Integrity Monitoring (FIM/syscheck) events.

    Queries alerts with syscheck data — file additions, modifications,
    and deletions on monitored paths. Use for 'what files changed on X',
    'was /etc/passwd modified?', 'show me FIM events for the last hour',
    'what did the attacker change?'.

    agent_name: filter to a specific agent. Omit for all agents.
    path_contains: substring of the file path (e.g. '/etc/', 'cron', 'authorized_keys').
    time_window: '24h', '7d', '30d'. Default '24h'.
    limit: max results (1-100). Default 30.
    """
    body: Dict[str, Any] = {
        "size": min(max(int(limit), 1), 100),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            {"range":  {"@timestamp": {"gte": f"now-{time_window}"}}},
            # FIM events always have syscheck in their rule groups
            {"bool": {"should": [
                {"match_phrase": {"rule.groups": "syscheck"}},
                {"match_phrase": {"rule.groups": "fim"}},
            ], "minimum_should_match": 1}},
        ]}},
    }
    must = body["query"]["bool"]["must"]

    if agent_name:
        must.append({"match_phrase": {"agent.name": agent_name}})

    if path_contains:
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
        logger.warning("agent_tools.get_fim_events.failed: %s", exc)
        return {"total": 0, "events": [], "error": str(exc)}

    hits = data.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    events = []
    for h in hits.get("hits", []):
        src = h.get("_source", {})
        syscheck = src.get("syscheck", {}) or {}
        rule = src.get("rule", {}) or {}
        agent = src.get("agent", {}) or {}
        events.append({
            "timestamp":   src.get("timestamp") or src.get("@timestamp"),
            "agent_name":  agent.get("name"),
            "path":        syscheck.get("path"),
            "event":       syscheck.get("event"),      # added / modified / deleted
            "size_before": syscheck.get("size_before"),
            "size_after":  syscheck.get("size_after"),
            "md5_before":  syscheck.get("md5_before"),
            "md5_after":   syscheck.get("md5_after"),
            "uid_after":   syscheck.get("uid_after"),
            "gid_after":   syscheck.get("gid_after"),
            "perm_after":  syscheck.get("perm_after"),
            "rule_id":     rule.get("id"),
            "rule_desc":   rule.get("description"),
            "_id":         h.get("_id"),
            "_index":      h.get("_index"),
        })

    # Classify FIM events by path
    _NORMAL_PATHS = ["/tmp/ansible", "/etc/cups", "/var/log", "ansible_payload",
                     "AppData\\Temp", "\\Windows\\Temp", "\\Windows\\SoftwareDistribution",
                     "/run/systemd", "/proc/", "/.cache/"]
    _SUSPICIOUS_PATHS = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/",
                         "/bin/", "/usr/bin/", "/sbin/", "/.ssh/", "/etc/cron",
                         "System32\\drivers", "system32\\config", "\\startup",
                         "lsass", "mimikatz", "/boot/", "/etc/systemd/system/"]

    def _classify_fim(path):
        p = path or ""
        if any(s in p for s in _SUSPICIOUS_PATHS): return "🔴 SUSPICIOUS"
        if any(s in p for s in _NORMAL_PATHS): return "⚪ NORMAL"
        return "🟡 REVIEW"

    suspicious = [e for e in events if _classify_fim(e.get("path","")) == "🔴 SUSPICIOUS"]
    review     = [e for e in events if _classify_fim(e.get("path","")) == "🟡 REVIEW"]
    normal     = [e for e in events if _classify_fim(e.get("path","")) == "⚪ NORMAL"]

    rows = [
        f"**{total:,} FIM events** (showing {len(events)}, last {time_window}) — "
        f"🔴 {len(suspicious)} suspicious | 🟡 {len(review)} review | ⚪ {len(normal)} normal\n",
        "| Class | Time (UTC) | Event | Path | Permissions | Size |",
        "|---|---|---|---|---|---|"
    ]
    for e in events:
        ts   = (e.get("timestamp") or "—")[:19].replace("T"," ")
        evt  = e.get("event") or e.get("event_type") or "change"
        path = e.get("path") or "—"
        perm = e.get("perm_after") or e.get("perm_before") or "—"
        size = e.get("size_after") or e.get("size_before") or "—"
        cls  = _classify_fim(path)
        rows.append(f"| {cls} | {ts} | {evt} | {path} | {perm} | {size} |")
    fmt = "\n".join(rows)
    return {"total": total, "returned": len(events), "time_window": time_window, "events": events, "formatted": fmt}


# ─── Tool: execute_playbook ───────────────────────────────────────────

# Playbooks exposed to the chatbot (subset of the full set — excludes
# destructive-without-IP playbooks that need richer context to be safe).
_CHATBOT_ALLOWED_PLAYBOOKS = {
    "block_ip",
    "incident_response",
    "win_incident_response",
    "fim_restore_response",
    "win_fim_restore_response",
    "harden_nginx_tls",
    "mysql_credential_response",
    "block_adcs_abuse",
    "block_dns_exfil",
    "brute_force_response",
    "win_brute_force_response",
    "lateral_movement_response",
    "win_lateral_movement_response",
    "compromised_user_response",
    "malware_containment",
}


def execute_playbook(
    playbook: str,
    target_host: str,
    confirmed: bool = False,
    source_ip: Optional[str] = None,
    reason: Optional[str] = None,
    username: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute an Ansible response playbook on a target host (two-phase confirmation).
    USE ONLY when the user explicitly asks to RUN/EXECUTE/BLOCK/ISOLATE something.
    DO NOT use to LIST or CHECK what playbooks ran — use get_incidents for that.
    CRITICAL — always call with confirmed=False first. This returns a
    preview of what will happen and asks the user to confirm. Only call
    with confirmed=True after the user explicitly says 'confirm', 'yes',
    'do it', 'go ahead', or similar.

    Available playbooks: block_ip, incident_response, win_incident_response,
    fim_restore_response, win_fim_restore_response, harden_nginx_tls,
    mysql_credential_response, block_adcs_abuse, block_dns_exfil,
    brute_force_response, win_brute_force_response, lateral_movement_response,
    win_lateral_movement_response, compromised_user_response, malware_containment.
    Required extra params by playbook:
    - block_adcs_abuse: ca_name=SENTINEL-LAB-CA, template_name=SentinelVulnESC1
    - compromised_user_response: username=<account to disable> — source_ip is NOT required, pass username only
    - malware_containment: file_path=<path>, malware_process=<name>, malware_pid=<pid>

    playbook: name of the playbook to run.
    target_host: Wazuh agent name (e.g. 'srv-web', 'srv-ad-dns'). Never 'all'.
    confirmed: False = show confirmation prompt, True = actually execute.
    source_ip: attacker IP to block (required for block_ip and brute force playbooks).
    reason: why you are running this (written to the incident audit log).
    """
    # Coerce confirmed — LLMs sometimes send string "false"/"true" instead of boolean
    if isinstance(confirmed, str):
        confirmed = confirmed.strip().lower() not in ("false", "0", "no", "")
    import requests as _req
    import uuid as _uuid
    from ai_agents.config import get_settings

    s = get_settings()
    base_url = f"http://{s.ansible_runner_host}:{s.ansible_runner_port}"

    # Normalise target_host — try to resolve short names to real agent names
    # First check a static alias map (common short names), then fuzzy-match
    # against the live Wazuh agent list.
    _STATIC_ALIASES = {
        "web": "web", "webserver": "web", "dns": "dns", "bind": "dns",
        "sql": "sql", "mysql": "sql", "db": "sql", "ad": "ad",
        "dc": "ad", "ftp": "ftp", "fw": "fw", "firewall": "fw",
        "gateway": "fw",
    }
    _normalized = target_host.lower().strip()
    _keyword    = _STATIC_ALIASES.get(_normalized, _normalized)
    try:
        from ai_agents.config_topology import get_topology as _topo_fn
        _agents = _topo_fn().get_all_agents()
        # Exact match first
        _exact = next((a["name"] for a in _agents if a["name"].lower() == _normalized), None)
        if _exact:
            target_host = _exact
        else:
            # Keyword substring match
            _fuzzy = next((a["name"] for a in _agents if _keyword in a["name"].lower()), None)
            if _fuzzy:
                target_host = _fuzzy
    except Exception:
        pass  # keep original if topology unavailable

    # Validate playbook name
    if playbook not in _CHATBOT_ALLOWED_PLAYBOOKS:
        return {
            "error": (
                f"Playbook '{playbook}' is not available via the chatbot. "
                f"Available: {sorted(_CHATBOT_ALLOWED_PLAYBOOKS)}"
            )
        }

    # Validate target_host — never allow 'all'
    if not target_host or target_host.strip().lower() in ("all", "", "none"):
        return {"error": "target_host must be a specific agent name (e.g. 'srv-web'), never 'all'."}

    # Safety: block_ip and brute_force variants require a source IP
    _ip_required = {
        "block_ip", "brute_force_response", "win_brute_force_response",
        "lateral_movement_response", "win_lateral_movement_response",
    }
    if playbook in _ip_required and not source_ip:
        return {"error": f"Playbook '{playbook}' requires source_ip (the attacker's IP address)."}

    # Safety: never block loopback or management subnet
    if source_ip:
        try:
            from ai_agents.config_topology import get_topology as _topo_fn2
            if not _topo_fn2().is_safe_to_block(source_ip):
                return {
                    "error": f"Refusing to block protected IP '{source_ip}' "
                             f"(loopback or management subnet per SENTINEL_MANAGEMENT_SUBNETS)."
                }
        except Exception:
            # Fallback safety check if topology unavailable
            import ipaddress as _ipa
            try:
                _addr = _ipa.ip_address(source_ip)
                if _addr.is_loopback:
                    return {"error": f"Refusing to block loopback IP '{source_ip}'."}
            except ValueError:
                pass

    # ── Phase 1: Confirmation prompt ─────────────────────────────────
    if not confirmed:
        action_lines = [f"**Playbook**: `{playbook}`", f"**Target host**: `{target_host}`"]
        if source_ip:
            action_lines.append(f"**Source IP to block**: `{source_ip}`")
        if username:
            action_lines.append(f"**Username**: `{username}`")
        if reason:
            action_lines.append(f"**Reason**: {reason}")

        msg = (
            "⚠️ **Confirmation required** before executing:\n\n"
            + "\n".join(f"- {l}" for l in action_lines)
            + "\n\nReply **confirm** to proceed or **cancel** to abort."
        )
        return {
            "status":    "pending_confirmation",
            "playbook":  playbook,
            "target_host": target_host,
            "source_ip": source_ip,
            "message":   msg,
            "formatted": msg,
        }

    # ── Phase 2: Execute ──────────────────────────────────────────────
    incident_id = f"chat_{_uuid.uuid4().hex[:8]}"
    extra_vars: Dict[str, Any] = {
        "target_hosts": target_host,
        "source_ip":    source_ip or "",
        "incident_id":  incident_id,
        "severity":     "high",
        "dry_run":      False,
    }
    if source_ip:
        extra_vars["block_ip_address"] = source_ip

    try:
        resp = _req.post(
            f"{base_url}/run",
            json={"playbook": playbook, "extra_vars": extra_vars},
            timeout=120,
        )
        resp.raise_for_status()
        result = resp.json()
    except Exception as exc:
        logger.error("agent_tools.execute_playbook.runner_failed: %s", exc)
        return {"error": f"Ansible runner call failed: {exc}", "playbook": playbook}

    # Write to Postgres incidents table for audit trail
    try:
        from ai_agents.database.db_manager import get_db
        from ai_agents.database.models import Incident, IncidentStatus, SeverityLevel
        with get_db() as db:
            db.add(Incident(
                id=incident_id,
                rule_id=0,
                    wazuh_alert_id=f"chat_{incident_id}",
                rule_description=reason or f"Chat-commanded: {playbook} on {target_host}",
                severity=SeverityLevel.HIGH,
                status=IncidentStatus.RESPONDING,
                source_ip=source_ip,
                analysis=(
                    f"Manually triggered via SENTINEL-AI chatbot. "
                    f"Playbook: {playbook}. Target: {target_host}. "
                    f"Reason: {reason or 'no reason given'}."
                ),
                recommended_action=playbook,
                playbook_executed=playbook,
                playbook_result=result,
                confidence_score=1.0,
                alert_data={"source": "chat_command", "target_host": target_host, "source_ip": source_ip},
            ))
    except Exception as db_exc:
        logger.warning("agent_tools.execute_playbook.db_write_failed: %s", db_exc)

    rc = result.get("rc", -1)
    ansible_status = result.get("status", "unknown")
    summary = result.get("summary", {})

    changed = summary.get("changed", 0)
    failed  = summary.get("failed", 0)
    ok      = summary.get("ok", 0)
    # Explicit outcome — model must report this verbatim
    if rc != 0 or failed > 0:
        outcome = f"FAILED (rc={rc}, failed_tasks={failed})"
    elif changed == 0 and ok == 0:
        outcome = "FAILED — host not found in inventory or no tasks ran (changed=0, ok=0). Target host name may be wrong."
    else:
        outcome = f"SUCCESS (changed={changed}, ok={ok})"
    icon = "✅" if (rc == 0 and failed == 0 and (changed > 0 or ok > 0)) else "❌"
    changed_list = "\n".join(f"  - {t.get('outcome',t.get('task',''))}" for t in result.get("changed_tasks",[])[:5])
    fmt = (
        f"{icon} **{playbook}** on `{target_host}`\n"
        f"**Outcome:** {outcome}"
        + (f"\n**Changed tasks:**\n{changed_list}" if changed_list else "")
    )
    return {
        "outcome":        outcome,
        "success":        rc == 0 and failed == 0 and (changed > 0 or ok > 0),
        "status":         "executed",
        "incident_id":    incident_id,
        "playbook":       playbook,
        "target_host":    target_host,
        "source_ip":      source_ip,
        "rc":             rc,
        "ansible_status": ansible_status,
        "ok":             ok,
        "changed":        changed,
        "failed":         failed,
        "changed_tasks":  result.get("changed_tasks", [])[:5],
        "failed_tasks":   result.get("failed_tasks", []),
        "formatted":      fmt,
    }


# ─── Tool: get_active_blocks ──────────────────────────────────────────


def get_active_blocks(
    source_ip: Optional[str] = None,
    agent_name: Optional[str] = None,
    time_window: str = "7d",
    live_check: bool = False,
) -> Dict[str, Any]:
    """Check what IP blocks are currently active in the SENTINEL-AI system.

    Queries the incidents database for executed block_ip and block_dns_exfil
    playbooks. Use for 'is 10.70.0.10 blocked?', 'why was this IP banned?',
    'what did you block today?', 'show me all active blocks'.

    source_ip: check if a specific IP is blocked (e.g. '10.70.0.10').
    agent_name: filter blocks on a specific agent. Omit for all agents.
    time_window: '24h', '7d', '30d'. Default '7d'.
    live_check: if True, also queries live iptables/Windows Firewall state via Ansible.
    """
    from datetime import datetime, timedelta
    from ai_agents.database.db_manager import get_db
    from ai_agents.database.models import Incident

    try:
        unit = time_window[-1].lower()
        n    = int(time_window[:-1])
        delta = {"m": timedelta(minutes=n), "h": timedelta(hours=n),
                 "d": timedelta(days=n)}.get(unit, timedelta(days=7))
    except (ValueError, IndexError):
        delta = timedelta(days=7)
    cutoff = datetime.utcnow() - delta

    _block_playbooks = ("block_ip", "block_dns_exfil", "brute_force_response",
                        "win_brute_force_response", "lateral_movement_response",
                        "win_lateral_movement_response")

    try:
        with get_db() as db:
            q = db.query(Incident).filter(
                Incident.created_at >= cutoff,
                Incident.playbook_executed.in_(_block_playbooks),
            )
            if source_ip:
                q = q.filter(Incident.source_ip == source_ip)
            rows = q.order_by(Incident.created_at.desc()).limit(50).all()

            blocks = []
            for r in rows:
                # Resolve target agent from alert_data if available
                alert_data = r.alert_data or {}
                # Chat-triggered: alert_data has "target_host" directly
                # Automated triage: alert_data is the raw Wazuh alert with agent.name
                target = (
                    alert_data.get("target_host")
                    or alert_data.get("target_hosts")
                    or (alert_data.get("agent") or {}).get("name")
                    or "unknown"
                )
                if agent_name and target != agent_name:
                    continue
                if not r.source_ip or r.source_ip.strip() == "":
                    continue
                blocks.append({
                    "incident_id":      r.id,
                    "blocked_ip":       r.source_ip,
                    "target_agent":     target,
                    "playbook":         r.playbook_executed,
                    "reason":           r.rule_description,
                    "blocked_at":       r.created_at.isoformat() if r.created_at else None,
                    "trigger":          "chat_command" if r.rule_id == 0 else f"rule_{r.rule_id}",
                })

            if source_ip:
                is_blocked = any(b["blocked_ip"] == source_ip for b in blocks)
                return {
                    "queried_ip": source_ip,
                    "is_blocked": is_blocked,
                    "block_count": len(blocks),
                    "blocks": blocks,
                }

            rows = ["| Blocked IP | Target Host | Playbook | Reason | Blocked At |", "|---|---|---|---|---|"]
            for b in blocks:
                ip = b.get("blocked_ip") or "—"
                if ip == "—": continue
                host = b.get("target_agent","—")
                pb = b.get("playbook","—")
                reason = (b.get("reason") or "—")[:50]
                ts = (b.get("blocked_at") or "—")[:19].replace("T"," ")
                rows.append(f"| {ip} | {host} | {pb} | {reason} | {ts} |")
            valid_blocks = [b for b in blocks if b.get("blocked_ip","").strip()]
            fmt = f"**{len(valid_blocks)} recorded block(s)** in the last {time_window} (from SENTINEL-AI dispatch log):\n\n" + "\n".join(rows) if valid_blocks else f"No block operations recorded in the last {time_window}."
            return {
                "total_blocks": len(blocks),
                "time_window":  time_window,
                "blocks":       blocks,
                "formatted":    fmt,
            }
    except Exception as exc:
        logger.warning("agent_tools.get_active_blocks.failed: %s", exc)
        return {"error": str(exc)}


# ─── Tool: get_sca_results ────────────────────────────────────────────


def get_sca_results(
    agent_name: str,
    limit: int = 20,
) -> Dict[str, Any]:
    """Get Security Configuration Assessment (SCA/CIS benchmark) results for an agent.

    Wazuh SCA periodically checks agents against CIS benchmarks and reports
    passed/failed/not-applicable checks. Use for 'CIS compliance status of
    srv-web', 'what security checks failed on srv-sql', 'hardening status'.

    agent_name: exact agent name.
    limit: max checks to return (1-100). Default 20.
    """
    if not agent_name:
        return {"error": "agent_name required"}

    agent_id = _agent_id_from_name(agent_name)
    if agent_id is None:
        return {"error": f"Agent '{agent_name}' not found"}

    try:
        client = _get_client()

        # Get SCA policies for this agent
        policy_data = client._manager_request(
            "GET", f"/sca/{agent_id}",
            params={"limit": 10},
        )
        policies = policy_data.get("data", {}).get("affected_items", [])
        if not policies:
            return {
                "agent_name": agent_name,
                "message": "No SCA policies found for this agent. SCA may not be configured.",
                "policies": [],
            }

        # Gather checks from the first (most relevant) policy
        policy_id = policies[0].get("policy_id")
        checks_data = client._manager_request(
            "GET", f"/sca/{agent_id}/checks/{policy_id}",
            params={"limit": min(max(int(limit), 1), 100)},
        )
        checks = checks_data.get("data", {}).get("affected_items", [])
        total  = checks_data.get("data", {}).get("total_affected_items", len(checks))

        # Summary counts
        passed   = sum(1 for c in checks if c.get("result") == "passed")
        failed   = sum(1 for c in checks if c.get("result") == "failed")
        not_appl = sum(1 for c in checks if c.get("result") == "not applicable")

        # Compact check representation
        compact_checks = []
        for c in checks:
            compact_checks.append({
                "id":          c.get("id"),
                "title":       c.get("title"),
                "result":      c.get("result"),
                "description": (c.get("description") or "")[:200],
                "remediation": (c.get("remediation") or "")[:200],
                "rationale":   (c.get("rationale") or "")[:150],
            })

        p_name = policies[0].get("name","—")
        summary_str = f"Passed: {passed} | Failed: {failed} | N/A: {not_appl} | Score: {policies[0].get('score','—')}%"
        rows = ["| Result | Title | Rationale |", "|---|---|---|"]
        for c in compact_checks[:20]:
            icon = "✅" if c.get("result") == "passed" else ("❌" if c.get("result") == "failed" else "➖")
            title = (c.get("title") or "—")[:55]
            rat = (c.get("rationale") or "—")[:45]
            rows.append(f"| {icon} {c.get('result','—')} | {title} | {rat} |")
        fmt = f"**SCA: {p_name}** on {agent_name}\n**{summary_str}**\n\n" + "\n".join(rows)
        return {
            "agent_name":   agent_name,
            "policy_name":  p_name,
            "policy_id":    policy_id,
            "total_checks": total,
            "returned":     len(compact_checks),
            "summary": {
                "passed":         passed,
                "failed":         failed,
                "not_applicable": not_appl,
                "score_pct":      policies[0].get("score"),
            },
            "checks":    compact_checks,
            "formatted": fmt,
        }
    except Exception as exc:
        logger.warning("agent_tools.get_sca_results.failed: %s", exc)
        return {"error": str(exc)}


# =============================================================================


from collections import defaultdict
from datetime import datetime, timezone


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO8601 timestamp string to datetime. Returns None on failure."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _alert_to_context_record(src: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract every field needed for deduplication and LLM context
    from a raw OpenSearch _source document.
    Extends _alert_to_summary with syscheck and full MITRE fields.
    """
    rule      = src.get("rule", {}) or {}
    agent     = src.get("agent", {}) or {}
    data      = src.get("data", {}) or {}
    syscheck  = src.get("syscheck", {}) or {}
    alert_sub = data.get("alert", {}) or {}
    mitre     = rule.get("mitre", {}) or {}

    _win_ed = ((data.get("win") or {}).get("eventdata") or {})
    src_ip = (
        data.get("srcip") or data.get("src_ip")
        or _win_ed.get("ipAddress")
        or _win_ed.get("sourceIp")
        or _win_ed.get("clientAddress")
    )

    # MITRE: stored as lists in Wazuh 4.x
    mitre_ids   = mitre.get("id", [])   or []
    mitre_techs = mitre.get("technique", []) or []
    mitre_id   = mitre_ids[0]   if mitre_ids   else ""
    mitre_tech = mitre_techs[0] if mitre_techs else ""

    return {
        "timestamp":          src.get("timestamp") or src.get("@timestamp"),
        "rule_id":            str(rule.get("id", "")),
        "rule_level":         rule.get("level", 0),
        "rule_description":   rule.get("description", ""),
        "rule_groups":        rule.get("groups", []),
        "agent_name":         agent.get("name", ""),
        "agent_ip":           agent.get("ip", ""),
        "src_ip":             (
                                "[local-execution]" if src_ip in ("::1","127.0.0.1","0:0:0:0:0:0:0:1")
                                else src_ip or ""
                              ),
        "dst_ip":             data.get("dstip") or data.get("dest_ip") or "",
        "dest_port":          data.get("dest_port") or data.get("dstport"),
        "proto":              data.get("proto", ""),
        "suricata_signature": alert_sub.get("signature", ""),
        "suricata_category":  alert_sub.get("category", ""),
        "syscheck_path":      syscheck.get("path", ""),
        "syscheck_event":     syscheck.get("event", ""),   # added/modified/deleted
        "syscheck_md5_after": syscheck.get("md5_after", ""),
        "mitre_technique_id":   mitre_id,
        "mitre_technique_name": mitre_tech,
        "mitre_all_ids":        mitre_ids,
    }


def _make_dedup_key(rec: Dict[str, Any]) -> tuple:
    """
    Three-tier uniqueness key:
      Tier 1 (FIM):     (rule_id, agent_name, syscheck_path)
      Tier 2 (Network): (rule_id, agent_name, src_ip)
      Tier 3 (Default): (rule_id, agent_name)
    """
    rule_id    = rec["rule_id"]
    agent_name = rec["agent_name"]
    syscheck   = rec["syscheck_path"]
    src_ip     = rec["src_ip"]

    if syscheck:
        return ("fim", rule_id, agent_name, syscheck)
    elif src_ip:
        return ("net", rule_id, agent_name, src_ip)
    else:
        return ("gen", rule_id, agent_name)


# ─── Tool: gather_alert_context ───────────────────────────────────────────────


def _fmt_context_analysis(unique_events: list, mitre_summary: list) -> str:
    """True alert correlation: group by attacker IP, detect attack chains, produce narrative."""
    import os as _os2
    from collections import defaultdict

    _raw_mgmt = _os2.getenv("SENTINEL_MANAGEMENT_SUBNETS", "10.60.0.0/24")
    _MGMT_PREFIXES = [ip.strip().split("/")[0].rsplit(".",1)[0]+"."
                      if "/" in ip.strip() else ip.strip()
                      for ip in _raw_mgmt.split(",") if ip.strip()]

    _NOISE_RULES = {506, 507, 508, 553, 554, 555, 5715, 40704,
                    19005, 19006, 19007, 594, 750}
    _NOISE_PATHS = ["/etc/cups", "/proc/", "/run/", "/tmp/ansible",
                    "subscriptions.conf", ".pyc"]

    def _is_mgmt(ip):
        return ip and any(ip.startswith(p) for p in _MGMT_PREFIXES)

    def _is_noise(e):
        rule_id = int(e.get("rule_id") or 0)
        if rule_id in _NOISE_RULES: return True
        path = e.get("syscheck_path") or ""
        src  = e.get("src_ip") or ""
        if rule_id in (550, 553, 554) and any(p in path for p in _NOISE_PATHS): return True
        if rule_id == 5715 and _is_mgmt(src): return True
        return False

    security_events = [e for e in unique_events if not _is_noise(e)]
    if not security_events:
        return "No notable security activity detected. All events are operational noise."

    # ── Phase 1: Group events by attacker IP ─────────────────────────────────
    # External IPs are attackers; internal non-mgmt IPs may be pivots
    by_src = defaultdict(list)
    no_src = []
    for e in security_events:
        src = (e.get("src_ip") or "").strip()
        if src and not _is_mgmt(src):
            by_src[src].append(e)
        else:
            no_src.append(e)

    # ── Phase 2: Detect attack phases per source IP ───────────────────────────
    _PHASE_KEYWORDS = {
        "reconnaissance": ["scan", "nmap", "port sweep", "discovery", "enum"],
        "initial_access": ["brute force", "login failure", "authentication fail",
                           "sql injection", "webshell", "exploit", "upload"],
        "execution":      ["powershell", "cmd=", "shell from", "base64", "encoded command",
                           "script", "process injection"],
        "persistence":    ["scheduled task", "registry", "startup", "service install",
                           "cron", "authorized_keys"],
        "credential":     ["kerberoast", "mimikatz", "credential", "lsass", "hash",
                           "shadow", "passwd", "ntlm"],
        "lateral":        ["lateral movement", "ntlm logon", "pass-the-hash",
                           "wmi", "psexec", "winrm from"],
        "exfiltration":   ["exfil", "dns tunnel", "doh", "data transfer", "loot"],
        "c2":             ["beacon", "c2", "command and control", "reverse shell"],
        "impact":         ["ransomware", "encrypt", "wipe", "malware dropped",
                           "executable file dropped"],
    }

    def _detect_phases(events):
        phases = {}
        for e in events:
            desc = (e.get("rule_description") or e.get("suricata_signature") or "").lower()
            for phase, keywords in _PHASE_KEYWORDS.items():
                if any(k in desc for k in keywords):
                    if phase not in phases:
                        phases[phase] = {"events": [], "occurrences": 0}
                    phases[phase]["events"].append(e)
                    phases[phase]["occurrences"] += e.get("occurrences", 1)
        return phases

    lines = []
    total_occ = sum(e.get("occurrences",1) for e in security_events)
    lines.append(f"**Security Assessment** — {len(security_events)} unique event types "
                 f"({total_occ:,} occurrences) from {len(by_src)} source IP(s)")
    lines.append("")

    # ── Phase 3: Per-attacker narrative ──────────────────────────────────────
    # Sort attackers by total occurrences descending
    ranked_srcs = sorted(by_src.items(),
                         key=lambda x: sum(e.get("occurrences",1) for e in x[1]),
                         reverse=True)

    for src_ip, events in ranked_srcs[:5]:
        phases = _detect_phases(events)
        total_src = sum(e.get("occurrences",1) for e in events)
        first_ts = min((e.get("first_seen") or "9999-01-01") for e in events if e.get("first_seen"))[:16].replace("T"," ") if any(e.get("first_seen") for e in events) else "—"
        last_ts  = max((e.get("last_seen")  or "0000-01-01") for e in events if e.get("last_seen"))[:16].replace("T"," ") if any(e.get("last_seen") for e in events) else "—"

        lines.append(f"**Attacker: `{src_ip}`** — {total_src} events | {first_ts} → {last_ts} UTC")

        if phases:
            # Build attack chain in logical order
            chain_order = ["reconnaissance","initial_access","execution","credential",
                           "lateral","persistence","exfiltration","c2","impact"]
            chain = [p for p in chain_order if p in phases]
            if chain:
                lines.append(f"  Attack chain: {' → '.join(p.replace('_',' ').title() for p in chain)}")

            for phase in chain:
                p_data = phases[phase]
                top_event = max(p_data["events"], key=lambda e: e.get("occurrences",1))
                desc = (top_event.get("rule_description") or top_event.get("suricata_signature") or "?")[:80]
                lines.append(f"  [{phase.replace('_',' ').upper()}] {desc} (×{p_data['occurrences']})")
        else:
            # No phase detected — show top events
            top = sorted(events, key=lambda e: e.get("occurrences",1), reverse=True)[:2]
            for e in top:
                desc = (e.get("rule_description") or "?")[:80]
                lines.append(f"  - {desc} × {e.get('occurrences',1)}")
        lines.append("")

    # ── Phase 4: Host-side events (no source IP) ─────────────────────────────
    if no_src:
        host_phases = _detect_phases(no_src)
        host_critical = [e for e in no_src if int(e.get("rule_level") or 0) >= 12]
        host_high     = [e for e in no_src if 9 <= int(e.get("rule_level") or 0) < 12]

        if host_critical or host_high:
            lines.append("**Host-side activity (no external source IP):**")
            for e in (host_critical + host_high)[:5]:
                desc = e.get("rule_description") or "?"
                occ  = e.get("occurrences", 1)
                ts   = (e.get("last_seen") or "")[:16].replace("T"," ")
                lines.append(f"  - [{int(e.get('rule_level',0))}] {desc} × {occ} (last: {ts})")
            lines.append("")

    # ── Phase 5: MITRE summary ────────────────────────────────────────────────
    if mitre_summary:
        techniques = []
        for m in mitre_summary[:6]:
            if not m: continue
            tid  = m.get("technique_id") or "?"
            name = m.get("technique_name") or ""
            occ  = m.get("total_occurrences","")
            techniques.append(f"{tid} ({name})" + (f" ×{occ}" if occ else ""))
        if techniques:
            lines.append(f"**MITRE ATT&CK:** {' · '.join(techniques)}")

    return "\n".join(lines)


def gather_alert_context(
    agent_name: Optional[str] = None,
    time_window: str = "30m",
    min_level: int = 0,
    keyword: Optional[str] = None,
    max_raw_alerts: int = 1000,
    max_unique_types: int = 100,
) -> Dict[str, Any]:
    """Fetch, deduplicate and compress alerts into structured LLM context.

    Instead of returning thousands of raw alert lines, this tool:
      1. Fetches up to max_raw_alerts alerts matching the filters
      2. Groups them by (rule_id, agent, src_ip/syscheck_path) — three-tier key
      3. First occurrence of each group is kept as a full record
      4. Subsequent occurrences only increment the counter
      5. Returns N unique event types (N <= max_unique_types) each with:
         occurrences, first_seen, last_seen, duration_minutes, rate_per_minute

    The LLM sees a 10:1 to 100:1 compressed view — full visibility with no
    context waste on repetitive noise.

    Use this for:
      - Unknown-rule triage (orchestrator Phase 3 hook)
      - "Give me a summary of what's happening on agent X"
      - Any question requiring a panoramic view of recent activity

    agent_name: filter to a specific agent. Omit for all agents.
    time_window: dynamic — '15m', '30m', '1h', '6h', '24h', '7d', '30d'.
                 Natural language: 'week'='7d', 'month'/'weeks'='30d' (max).
                 Default '30m'.
    min_level: minimum Wazuh rule level (0-15). Default 0.
    keyword: case-insensitive substring to search across rule descriptions,
             Suricata signatures, rule groups, and file paths.
             Examples: 'scan', 'SCAN', 'Scan', 'nmap', 'reverse shell', 'doH'.
             If specified and not found in time_window, auto-expands up to 30d.
             Returns explicit not-found if absent within 30d.
    max_raw_alerts: max raw docs to fetch before deduplication (1-2000).
    max_unique_types: max unique event types in output (1-200). Default 100.
    """
    # ── 1. Fetch raw alerts from OpenSearch ───────────────────────────────────
    body: Dict[str, Any] = {
        "size": min(max(int(max_raw_alerts), 1), 2000),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": f"now-{time_window}"}}},
        ]}},
        "_source": [
            "timestamp", "@timestamp",
            "rule.id", "rule.level", "rule.description", "rule.groups", "rule.mitre",
            "agent.name", "agent.ip",
            "data.srcip", "data.src_ip", "data.dstip", "data.dest_ip",
            "data.dest_port", "data.dstport", "data.proto",
            "data.alert.signature", "data.alert.category",
            "data.win.eventdata.ipAddress",
            "syscheck.path", "syscheck.event", "syscheck.md5_after",
        ],
    }
    must = body["query"]["bool"]["must"]

    if agent_name:
        must.append({"match_phrase": {"agent.name": agent_name}})
    if min_level > 0:
        must.append({"range": {"rule.level": {"gte": int(min_level)}}})

    try:
        data = _get_client()._indexer_request(
            "POST", "/wazuh-alerts-4.x-*/_search",
            json=body,
            headers={"Content-Type": "application/json"},
        )
    except Exception as exc:
        logger.warning("agent_tools.gather_alert_context.fetch_failed: %s", exc)
        return {"error": str(exc), "unique_events": [], "summary": {}}

    hits       = data.get("hits", {})
    total_raw  = hits.get("total", {}).get("value", 0)
    raw_hits   = hits.get("hits", [])
    # Secondary fetch: pull priority rules in small batches so no single rule drowns others
    _PRIORITY_RULE_GROUPS = [
        ["100534","100535","100536"],          # AD-CS ESC1
        ["100710","100711"],                    # Kerberoasting
        ["100114","100115"],                    # Falco sensitive reads
        ["100411","100412"],                    # DoH exfiltration
        ["100610","100611"],                    # MySQL credential access
        ["92213"],                              # Malware drop
    ]
    _prio_agent_filter = [{"match_phrase": {"agent.name": agent_name}}] if agent_name else []
    _all_prio_hits = []
    try:
        for _rgroup in _PRIORITY_RULE_GROUPS:
            _pb = {
                "size": 5,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": [
                    {"terms": {"rule.id": _rgroup}},
                    {"range": {"@timestamp": {"gte": f"now-{time_window}"}}},
                ] + _prio_agent_filter}},
                "_source": body["_source"],
            }
            _pd = _get_client()._indexer_request(
                "POST", "/wazuh-alerts-4.x-*/_search",
                json=_pb, headers={"Content-Type": "application/json"},
            )
            _all_prio_hits.extend(_pd.get("hits", {}).get("hits", []))
        if _all_prio_hits:
            raw_hits = _all_prio_hits + raw_hits
    except Exception as _pe:
        logger.warning("gather_alert_context.priority_fetch: %s", _pe)

    if not raw_hits:
        return {
            "summary": {
                "total_raw_alerts": total_raw,
                "unique_event_types": 0,
                "time_window": time_window,
                "agent_filter": agent_name or "all",
                "compression_ratio": "N/A",
            },
            "mitre_summary": [],
            "unique_events": [],
            "hint": f"No alerts in the last {time_window}. Try a longer time_window.",
        }

    # ── 2. Parse + deduplicate ────────────────────────────────────────────────
    # groups: key → {first_record, first_ts, last_ts, occurrences}
    groups: Dict[tuple, Dict[str, Any]] = {}

    for h in raw_hits:
        rec = _alert_to_context_record(h.get("_source", {}))
        key = _make_dedup_key(rec)
        ts  = _parse_iso(rec["timestamp"])

        if key not in groups:
            groups[key] = {
                "record":      rec,
                "first_seen":  ts,
                "last_seen":   ts,
                "occurrences": 1,
            }
        else:
            g = groups[key]
            g["occurrences"] += 1
            if ts:
                if g["first_seen"] is None or ts < g["first_seen"]:
                    g["first_seen"] = ts
                if g["last_seen"] is None or ts > g["last_seen"]:
                    g["last_seen"] = ts

    # ── 3. Sort: highest occurrences first, then most recent ─────────────────
    sorted_groups = sorted(
        groups.values(),
        key=lambda g: (g["occurrences"], g["last_seen"] or datetime.min.replace(tzinfo=timezone.utc)),
        reverse=True,
    )

    # ── 3b. Keyword filter + auto-expand to 30d ─────────────────────────────────
    _MAX_WINDOW = "30d"

    def _matches_keyword(g: dict, kw: str) -> bool:
        """Case-insensitive keyword match across all text fields of an event."""
        kw_lower = kw.lower()
        rec = g["record"]
        fields = [
            rec.get("rule_description", "") or "",
            rec.get("suricata_signature", "") or "",
            rec.get("suricata_category", "") or "",
            rec.get("syscheck_path", "") or "",
            rec.get("syscheck_event", "") or "",
            rec.get("proto", "") or "",
            " ".join(rec.get("rule_groups", []) or []),
            " ".join(rec.get("mitre_all_ids", []) or []),
            rec.get("mitre_technique_name", "") or "",
            rec.get("src_ip", "") or "",
        ]
        return any(kw_lower in f.lower() for f in fields if f)

    if keyword:
        # When a keyword is given, we cannot rely on the top-N recency fetch
        # because the matching alerts may be buried under thousands of recent
        # noise events. Query OpenSearch directly with a text filter instead,
        # then deduplicate that targeted result set.
        def _fetch_with_keyword(tw: str) -> list:
            kw_body = {
                "size": min(max(int(max_raw_alerts), 1), 2000),
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": [
                    {"range": {"@timestamp": {"gte": f"now-{tw}"}}},
                    {"bool": {"should": [
                        {"match": {"rule.description": keyword}},
                        {"match": {"data.alert.signature": keyword}},
                        {"match": {"rule.groups": keyword}},
                        {"wildcard": {"rule.description":
                            {"value": f"*{keyword}*", "case_insensitive": True}}},
                        {"wildcard": {"data.alert.signature":
                            {"value": f"*{keyword}*", "case_insensitive": True}}},
                        {"wildcard": {"syscheck.path":
                            {"value": f"*{keyword}*", "case_insensitive": True}}},
                    ], "minimum_should_match": 1}},
                ]}},
                "_source": body.get("_source", []),
            }
            if agent_name:
                kw_body["query"]["bool"]["must"].append(
                    {"match_phrase": {"agent.name": agent_name}}
                )
            if min_level > 0:
                kw_body["query"]["bool"]["must"].append(
                    {"range": {"rule.level": {"gte": int(min_level)}}}
                )
            try:
                kw_data = _get_client()._indexer_request(
                    "POST", "/wazuh-alerts-4.x-*/_search",
                    json=kw_body,
                    headers={"Content-Type": "application/json"},
                )
                return kw_data.get("hits", {}).get("hits", [])
            except Exception:
                return []

        kw_hits = _fetch_with_keyword(time_window)

        # Auto-expand to 30d if nothing found in requested window
        searched_window = time_window
        if not kw_hits and time_window != _MAX_WINDOW:
            logger.info("gather_alert_context.keyword_expanding",
                        keyword=keyword, from_window=time_window,
                        to_window=_MAX_WINDOW)
            kw_hits = _fetch_with_keyword(_MAX_WINDOW)
            searched_window = _MAX_WINDOW

        if not kw_hits:
            return {
                "summary": {
                    "total_raw_alerts":   total_raw,
                    "unique_event_types": 0,
                    "keyword":            keyword,
                    "searched_window":    _MAX_WINDOW,
                    "agent_filter":       agent_name or "all",
                },
                "mitre_summary":  [],
                "unique_events":  [],
                "not_found":      True,
                "message": (
                    f"No alerts matching keyword '{keyword}' found within "
                    f"the maximum search window of {_MAX_WINDOW}. "
                    f"This term does not appear in this environment's alert history."
                ),
            }

        # Deduplicate the keyword-filtered hits
        kw_groups: dict = {}
        for h in kw_hits:
            rec2 = _alert_to_context_record(h.get("_source", {}))
            key2 = _make_dedup_key(rec2)
            ts2  = _parse_iso(rec2["timestamp"])
            if key2 not in kw_groups:
                kw_groups[key2] = {"record": rec2, "first_seen": ts2,
                                   "last_seen": ts2, "occurrences": 1}
            else:
                gx = kw_groups[key2]
                gx["occurrences"] += 1
                if ts2:
                    if gx["first_seen"] is None or ts2 < gx["first_seen"]:
                        gx["first_seen"] = ts2
                    if gx["last_seen"] is None or ts2 > gx["last_seen"]:
                        gx["last_seen"] = ts2

        sorted_groups = sorted(
            kw_groups.values(),
            key=lambda g2: (g2["occurrences"],
                            g2["last_seen"] or datetime.min.replace(tzinfo=timezone.utc)),
            reverse=True,
        )
        time_window = searched_window
        # Skip the old post-dedup filter since we already queried by keyword
        filtered = sorted_groups  # all results already match

        if not filtered and time_window != _MAX_WINDOW:
            # Not found in requested window — silently expand to 30d and re-fetch
            logger.info(
                "gather_alert_context.keyword_expanding",
                keyword=keyword,
                from_window=time_window,
                to_window=_MAX_WINDOW,
            )
            try:
                exp_body = {
                    "size": min(max(int(max_raw_alerts), 1), 2000),
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "query": {"bool": {"must": [
                        {"range": {"@timestamp": {"gte": f"now-{_MAX_WINDOW}"}}},
                    ]}},
                    "_source": body.get("_source", []),
                }
                if agent_name:
                    exp_body["query"]["bool"]["must"].append(
                        {"match_phrase": {"agent.name": agent_name}}
                    )
                if min_level > 0:
                    exp_body["query"]["bool"]["must"].append(
                        {"range": {"rule.level": {"gte": int(min_level)}}}
                    )
                exp_data = _get_client()._indexer_request(
                    "POST", "/wazuh-alerts-4.x-*/_search",
                    json=exp_body,
                    headers={"Content-Type": "application/json"},
                )
                exp_hits_data = exp_data.get("hits", {})
                total_raw     = exp_hits_data.get("total", {}).get("value", total_raw)
                exp_raw_hits  = exp_hits_data.get("hits", [])

                # Re-deduplicate
                exp_groups: dict = {}
                for h in exp_raw_hits:
                    rec2 = _alert_to_context_record(h.get("_source", {}))
                    key2 = _make_dedup_key(rec2)
                    ts2  = _parse_iso(rec2["timestamp"])
                    if key2 not in exp_groups:
                        exp_groups[key2] = {"record": rec2, "first_seen": ts2,
                                            "last_seen": ts2, "occurrences": 1}
                    else:
                        gx = exp_groups[key2]
                        gx["occurrences"] += 1
                        if ts2:
                            if gx["first_seen"] is None or ts2 < gx["first_seen"]:
                                gx["first_seen"] = ts2
                            if gx["last_seen"] is None or ts2 > gx["last_seen"]:
                                gx["last_seen"] = ts2

                exp_sorted = sorted(
                    exp_groups.values(),
                    key=lambda g2: (
                        g2["occurrences"],
                        g2["last_seen"] or datetime.min.replace(tzinfo=timezone.utc),
                    ),
                    reverse=True,
                )
                filtered    = [g for g in exp_sorted if _matches_keyword(g, keyword)]
                time_window = _MAX_WINDOW  # update for summary
            except Exception as exp_exc:
                logger.warning("gather_alert_context.expand_failed: %s", exp_exc)
                filtered = []

        if not filtered:
            return {
                "summary": {
                    "total_raw_alerts":   total_raw,
                    "unique_event_types": 0,
                    "keyword":            keyword,
                    "searched_window":    _MAX_WINDOW,
                    "agent_filter":       agent_name or "all",
                },
                "mitre_summary":  [],
                "unique_events":  [],
                "not_found":      True,
                "message": (
                    f"No alerts matching keyword '{keyword}' found within "
                    f"the maximum search window of {_MAX_WINDOW}. "
                    f"This term does not appear in this environment's alert history."
                ),
            }

        # Keyword found — restrict output to matching events only
        sorted_groups = filtered

    # ── 4. Build output unique_events list ────────────────────────────────────
    unique_events = []
    all_timestamps = []

    # Priority rules always included regardless of dedup cutoff
    _PRIORITY_RULES = {
        "100534","100535","100536",  # AD-CS ESC1
        "100710","100711",            # Kerberoasting
        "100114","100115",            # Falco sensitive reads
        "100411","100412",            # DoH exfiltration
        "100610","100611",            # MySQL credential access
        "92213","92657",              # Malware drop / NTLM logon
    }
    priority_groups = [g for g in sorted_groups
                       if str(g["record"].get("rule_id","")) in _PRIORITY_RULES]
    normal_groups   = [g for g in sorted_groups
                       if str(g["record"].get("rule_id","")) not in _PRIORITY_RULES]
    sorted_groups   = priority_groups + normal_groups
    for g in sorted_groups[:max_unique_types]:
        rec        = g["record"]
        first_seen = g["first_seen"]
        last_seen  = g["last_seen"]
        occ        = g["occurrences"]

        # Duration and rate
        if first_seen and last_seen and first_seen != last_seen:
            duration_s   = (last_seen - first_seen).total_seconds()
            duration_min = round(duration_s / 60, 2)
            rate_per_min = round(occ / max(duration_min, 0.1), 2)
        else:
            duration_min = 0.0
            rate_per_min = float(occ)  # all at once

        first_str = first_seen.isoformat() if first_seen else None
        last_str  = last_seen.isoformat()  if last_seen  else None

        if first_seen:
            all_timestamps.append(first_seen)
        if last_seen:
            all_timestamps.append(last_seen)

        unique_events.append({
            "rule_id":              rec["rule_id"],
            "rule_description":     rec["rule_description"],
            "rule_level":           rec["rule_level"],
            "rule_groups":          rec["rule_groups"],
            "agent_name":           rec["agent_name"],
            "src_ip":               rec["src_ip"] or None,
            "dst_ip":               rec["dst_ip"] or None,
            "dest_port":            rec["dest_port"],
            "proto":                rec["proto"] or None,
            "suricata_signature":   rec["suricata_signature"] or None,
            "suricata_category":    rec["suricata_category"] or None,
            "syscheck_path":        rec["syscheck_path"] or None,
            "syscheck_event":       rec["syscheck_event"] or None,
            "mitre_technique_id":   rec["mitre_technique_id"] or None,
            "mitre_technique_name": rec["mitre_technique_name"] or None,
            "occurrences":          occ,
            "first_seen":           first_str,
            "last_seen":            last_str,
            "duration_minutes":     duration_min,
            "rate_per_minute":      rate_per_min,
        })

    # ── 5. MITRE summary ──────────────────────────────────────────────────────
    mitre_agg: Dict[str, Dict[str, Any]] = {}
    for g in sorted_groups:
        rec        = g["record"]
        tech_id    = rec["mitre_technique_id"]
        tech_name  = rec["mitre_technique_name"]
        if not tech_id:
            continue
        if tech_id not in mitre_agg:
            mitre_agg[tech_id] = {
                "technique_id":   tech_id,
                "technique_name": tech_name,
                "total_occurrences": 0,
                "unique_rules": set(),
            }
        mitre_agg[tech_id]["total_occurrences"] += g["occurrences"]
        mitre_agg[tech_id]["unique_rules"].add(rec["rule_id"])

    mitre_summary = sorted(
        [
            {
                "technique_id":      v["technique_id"],
                "technique_name":    v["technique_name"],
                "total_occurrences": v["total_occurrences"],
                "unique_rules":      sorted(v["unique_rules"]),
            }
            for v in mitre_agg.values()
        ],
        key=lambda x: x["total_occurrences"],
        reverse=True,
    )

    # ── 6. Global time range ──────────────────────────────────────────────────
    time_range = {}
    if all_timestamps:
        time_range = {
            "first": min(all_timestamps).isoformat(),
            "last":  max(all_timestamps).isoformat(),
        }

    unique_count     = len(groups)
    shown_count      = len(unique_events)
    compression      = f"{len(raw_hits)}:{unique_count}" if unique_count else "N/A"

    # ── Cross-agent correlation ─────────────────────────────────────────────
    import os as _os_corr
    _raw_mgmt2 = _os_corr.getenv("SENTINEL_MANAGEMENT_SUBNETS", "10.60.0.0/24")
    _mgmt2 = [ip.strip().split("/")[0].rsplit(".",1)[0]+"."
              if "/" in ip.strip() else ip.strip()
              for ip in _raw_mgmt2.split(",") if ip.strip()]

    def _is_external_ip(ip):
        if not ip or ip in ("::1","127.0.0.1","","[local-execution]","[management/ansible]"):
            return False
        return not any(ip.startswith(p) for p in _mgmt2)

    attacker_ips = list({e.get("src_ip","") for e in unique_events
                         if _is_external_ip(e.get("src_ip",""))})
    cross_agent_context = []

    if attacker_ips:
        try:
            for aip in attacker_ips[:3]:
                ca_data = _get_client()._indexer_request(
                    "POST", "/wazuh-alerts-4.x-*/_search",
                    json={"size": 50,
                          "sort": [{"@timestamp": {"order": "asc"}}],
                          "query": {"bool": {
                              "should": [
                                  {"term": {"data.srcip": aip}},
                                  {"term": {"data.src_ip": aip}},
                                  {"term": {"data.win.eventdata.ipAddress": aip}},
                                  {"term": {"data.win.eventdata.sourceIp": aip}},
                              ],
                              "minimum_should_match": 1,
                              "must_not": [{"term": {"agent.name": agent_name}}]
                                          if agent_name else []
                          }},
                          "_source": ["@timestamp","agent.name","rule.id",
                                      "rule.description","rule.level"]},
                    headers={"Content-Type": "application/json"}
                )
                ca_hits = ca_data.get("hits",{}).get("hits",[])
                if ca_hits:
                    cross_agent_context.append({
                        "attacker_ip": aip,
                        "other_agents_hit": list({h["_source"].get("agent",{}).get("name","") for h in ca_hits}),
                        "events": [{"ts": h["_source"].get("@timestamp","")[:16],
                                    "agent": h["_source"].get("agent",{}).get("name",""),
                                    "desc": h["_source"].get("rule",{}).get("description","")[:80],
                                    "level": h["_source"].get("rule",{}).get("level",0)}
                                   for h in ca_hits[:15]]
                    })
        except Exception as _ca_exc:
            logger.warning("gather_alert_context.cross_agent: %s", _ca_exc)

    # For local-execution events or no attacker IPs found,
    # check Suricata/firewall for connections TO this agent from external IPs
    if not attacker_ips and agent_name:
        try:
            import os as _os_fw
            gw_agent = _os_fw.getenv("SENTINEL_GATEWAY_AGENT", "sentinel-fw.sentinel.lab")
            # Get victim agent IP — from events or from Wazuh agent list
            victim_ips = list({e.get("agent_ip","") for e in unique_events if e.get("agent_ip")})
            if not victim_ips and agent_name:
                try:
                    ag = _agent_id_from_name(agent_name)
                    if ag:
                        ag_data = _get_client()._manager_request(
                            "GET", f"/agents/{ag}",
                            params={"select": "ip"}
                        )
                        ag_ip = ag_data.get("data",{}).get("affected_items",[{}])[0].get("ip","")
                        if ag_ip and ag_ip != "any":
                            victim_ips = [ag_ip]
                except Exception:
                    pass

            # Search Suricata alerts on the gateway for traffic TO victim agent IPs
            fw_must = [
                {"match": {"agent.name": gw_agent}},
                {"range": {"@timestamp": {"gte": f"now-{time_window}"}}},
            ]
            # Must have external source IP — use prefix range queries instead of term
            fw_must.append({"bool": {"should": [
                {"range": {"data.src_ip": {"gte": "10.70.0.0", "lte": "10.70.255.255"}}},
                {"range": {"data.srcip":  {"gte": "10.70.0.0", "lte": "10.70.255.255"}}},
            ], "minimum_should_match": 1}})
            if victim_ips:
                fw_must.append({"bool": {"should": [
                    {"term": {"data.dest_ip": vip}} for vip in victim_ips[:3]
                ] + [
                    {"term": {"data.dstip": vip}} for vip in victim_ips[:3]
                ], "minimum_should_match": 1}})

            fw_data = _get_client()._indexer_request(
                "POST", "/wazuh-alerts-4.x-*/_search",
                json={"size": 50,
                      "sort": [{"@timestamp": {"order": "asc"}}],
                      "query": {"bool": {"must": fw_must}},
                      "_source": ["@timestamp","rule.description","rule.level",
                                  "data.srcip","data.src_ip","data.dstip","data.dest_ip"]},
                headers={"Content-Type": "application/json"}
            )
            fw_hits = fw_data.get("hits",{}).get("hits",[])
            fw_attackers = {}
            for h in fw_hits:
                d = h["_source"]
                src = d.get("data",{}).get("srcip") or d.get("data",{}).get("src_ip","")
                if _is_external_ip(src):
                    if src not in fw_attackers:
                        fw_attackers[src] = []
                    fw_attackers[src].append({
                        "ts":   d.get("@timestamp","")[:16],
                        "desc": d.get("rule",{}).get("description","")[:80],
                        "level": d.get("rule",{}).get("level",0),
                    })
            for fw_ip, fw_events in sorted(fw_attackers.items(),
                                            key=lambda x: len(x[1]), reverse=True)[:3]:
                cross_agent_context.append({
                    "attacker_ip": fw_ip,
                    "note": f"Network traffic to {agent_name} detected via Suricata/pfSense gateway — scan/attack from {fw_ip}",
                    "gateway_events": fw_events[:10],
                    "other_agents_hit": [agent_name],
                })
        except Exception as _fw_exc:
            logger.warning("gather_alert_context.fw_lookup: %s", _fw_exc)

    # Also check Windows eventdata.ipAddress for foothold IPs
    if not attacker_ips and agent_name:
        try:
            fh_data = _get_client()._indexer_request(
                "POST", "/wazuh-alerts-4.x-*/_search",
                json={"size": 10,
                      "sort": [{"@timestamp": {"order": "desc"}}],
                      "query": {"bool": {"must": [
                          {"match": {"agent.name": agent_name}},
                          {"exists": {"field": "data.win.eventdata.ipAddress"}},
                          {"range": {"@timestamp": {"gte": "now-30d"}}}]}},
                      "_source": ["@timestamp","rule.description",
                                  "data.win.eventdata.ipAddress","rule.level"]},
                headers={"Content-Type": "application/json"}
            )
            for h in fh_data.get("hits",{}).get("hits",[]):
                fh_ip = (h["_source"].get("data",{}).get("win",{})
                         .get("eventdata",{}).get("ipAddress",""))
                if _is_external_ip(fh_ip):
                    cross_agent_context.append({
                        "attacker_ip": fh_ip,
                        "note": "Remote logon foothold IP from Windows event logs (may predate current window)",
                        "foothold_event": {
                            "ts":   h["_source"].get("@timestamp","")[:16],
                            "desc": h["_source"].get("rule",{}).get("description","")[:80],
                        }
                    })
                    break
        except Exception as _fh_exc:
            logger.warning("gather_alert_context.foothold: %s", _fh_exc)

    # Write-through cache to correlated_incidents
    try:
        import uuid as _uuid3
        from ai_agents.database.db_manager import get_db as _get_db3
        from ai_agents.database.models import CorrelatedIncident
        with _get_db3() as _db3:
            for _ca in cross_agent_context:
                _aip = _ca.get("attacker_ip","")
                if not _aip: continue
                _mids = [_m.get("technique_id","") for _m in mitre_summary[:3] if _m]
                for _mid in (_mids or [""]):
                    _db3.add(CorrelatedIncident(
                        id                  = f"CORR-{int(datetime.utcnow().timestamp())}-{_uuid3.uuid4().hex[:6]}",
                        shared_ip           = _aip,
                        combined_severity   = "high",
                        mitre_technique_id  = _mid or None,
                        mitre_technique_name= next((_m.get("technique_name") for _m in mitre_summary if _m.get("technique_id")==_mid), None),
                        attack_narrative    = _ca.get("note",""),
                        recommended_response= "investigate",
                        created_at          = datetime.utcnow(),
                    ))
            _db3.commit()
    except Exception as _corr_e:
        logger.debug("correlated_incidents_write_failed: %s", _corr_e)
    return {
        "summary": {
            "total_raw_alerts":   total_raw,
            "fetched_for_dedup":  len(raw_hits),
            "unique_event_types": unique_count,
            "shown_in_output":    shown_count,
            "time_window":        time_window,
            "agent_filter":       agent_name or "all",
            "compression_ratio":  compression,
            "time_range":         time_range,
        },
        "mitre_summary": mitre_summary,
        "unique_events":  unique_events,
        "cross_agent_correlation": cross_agent_context,
        # No pre-formatted field — LLM receives structured data and performs correlation
    }


import ipaddress as _ipaddress

# ─── Tool: enrich_ioc ────────────────────────────────────────────────────────

def enrich_ioc(
    ip: Optional[str] = None,
    file_hash: Optional[str] = None,
    domain: Optional[str] = None,
) -> Dict[str, Any]:
    """Enrich an Indicator of Compromise (IOC) with external threat intelligence.

    Queries multiple threat intelligence sources in parallel with per-source timeouts:
      - VirusTotal (70+ AV engines)
      - AbuseIPDB (IP reputation, abuse confidence score)
      - AlienVault OTX (community threat feeds) — 10s timeout, skipped if slow
      - IPinfo (geolocation, ASN)

    Only works for PUBLIC IPs — private/internal addresses are skipped immediately.

    ip: IP address to enrich (public IPs only)
    file_hash: MD5 or SHA256 hash to look up in VirusTotal
    domain: domain name to check
    """
    import ipaddress as _ipa
    import os as _os
    import requests as _req
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as _TimeoutError, as_completed

    results: Dict[str, Any] = {"ip": ip, "hash": file_hash, "domain": domain}

    if not (ip or file_hash or domain):
        return {"error": "Provide at least one of: ip, file_hash, domain"}

    # ── Private IP check ──────────────────────────────────────────────────────
    if ip:
        try:
            addr = _ipa.ip_address(ip)
            is_public = (
                not addr.is_private and not addr.is_loopback
                and not addr.is_reserved and not addr.is_link_local
                and not addr.is_multicast
            )
        except ValueError:
            return {"error": f"Invalid IP address: {ip}"}

        if not is_public:
            return {
                "ip": ip,
                "ip_intel": {
                    "skipped": True,
                    "reason": f"{ip} is a private/internal address — "
                              "no external threat intelligence available for RFC1918 ranges.",
                    "classification": "internal",
                },
            }

    # ── API keys ──────────────────────────────────────────────────────────────
    VT_KEY        = _os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSE_KEY     = _os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_KEY       = _os.getenv("OTX_API_KEY", "")
    IPINFO_TOKEN  = _os.getenv("IPINFO_TOKEN", "")

    ioc_value = ip or file_hash or domain
    ip_intel: Dict[str, Any] = {"ip": ioc_value, "sources": []}

    # ── Per-source query functions ─────────────────────────────────────────────
    def query_virustotal():
        if not VT_KEY:
            return "virustotal", {"skipped": True, "reason": "VIRUSTOTAL_API_KEY not set"}
        try:
            r = _req.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}",
                headers={"x-apikey": VT_KEY},
                timeout=15,
            )
            if r.status_code == 200:
                d = r.json().get("data", {}).get("attributes", {})
                stats = d.get("last_analysis_stats", {})
                return "virustotal", {
                    "malicious":   stats.get("malicious", 0),
                    "suspicious":  stats.get("suspicious", 0),
                    "harmless":    stats.get("harmless", 0),
                    "total":       sum(stats.values()),
                    "reputation":  d.get("reputation", 0),
                    "country":     d.get("country", ""),
                    "asn":         d.get("asn", ""),
                    "as_owner":    d.get("as_owner", ""),
                }
            return "virustotal", {"error": f"HTTP {r.status_code}"}
        except Exception as e:
            return "virustotal", {"error": str(e)[:80]}

    def query_abuseipdb():
        if not ABUSE_KEY:
            return "abuseipdb", {"skipped": True, "reason": "ABUSEIPDB_API_KEY not set"}
        try:
            r = _req.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSE_KEY, "Accept": "application/json"},
                params={"ipAddress": ioc_value, "maxAgeInDays": 90},
                timeout=10,
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                return "abuseipdb", {
                    "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                    "total_reports":          d.get("totalReports", 0),
                    "country":                d.get("countryCode", ""),
                    "isp":                    d.get("isp", ""),
                    "usage_type":             d.get("usageType", ""),
                    "is_tor":                 d.get("isTor", False),
                    "domain":                 d.get("domain", ""),
                }
            return "abuseipdb", {"error": f"HTTP {r.status_code}"}
        except Exception as e:
            return "abuseipdb", {"error": str(e)[:80]}

    def query_otx():
        if not OTX_KEY:
            return "otx", {"skipped": True, "reason": "OTX_API_KEY not set"}
        try:
            r = _req.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc_value}/general",
                headers={"X-OTX-API-KEY": OTX_KEY},
                timeout=10,   # hard 10s per-request timeout
            )
            if r.status_code == 200:
                d = r.json()
                pulse_count = d.get("pulse_info", {}).get("count", 0)
                return "otx", {
                    "pulse_count":      pulse_count,
                    "reputation":       d.get("reputation", 0),
                    "asn":              d.get("asn", ""),
                    "country":          d.get("country_name", ""),
                    "malware_families": d.get("pulse_info", {}).get("related", {})
                                         .get("alienvault", {}).get("malware_families", [])[:5],
                }
            return "otx", {"error": f"HTTP {r.status_code}"}
        except Exception as e:
            return "otx", {"skipped": True, "reason": f"timeout or error: {str(e)[:60]}"}

    def query_ipinfo():
        if not IPINFO_TOKEN:
            return "ipinfo", {"skipped": True, "reason": "IPINFO_TOKEN not set"}
        try:
            r = _req.get(
                f"https://ipinfo.io/lite/{ioc_value}",
                headers={"Authorization": f"Bearer {IPINFO_TOKEN}"},
                timeout=8,
            )
            if r.status_code == 200:
                d = r.json()
                return "ipinfo", {
                    "city":     d.get("city", ""),
                    "region":   d.get("region", ""),
                    "country":  d.get("country", ""),
                    "org":      d.get("org", ""),
                    "hostname": d.get("hostname", ""),
                }
            return "ipinfo", {"error": f"HTTP {r.status_code}"}
        except Exception as e:
            return "ipinfo", {"error": str(e)[:80]}

    # ── Run all queries in parallel, collect within 12s budget ───────────────
    queries = [query_virustotal, query_abuseipdb, query_otx, query_ipinfo]
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fn): fn.__name__ for fn in queries}
        for future in as_completed(futures, timeout=12):
            try:
                source, data = future.result()
                ip_intel[source] = data
                if not data.get("skipped") and not data.get("error"):
                    ip_intel["sources"].append(source)
            except _TimeoutError:
                pass
            except Exception as exc:
                logger.warning("enrich_ioc.source_failed %s: %s", futures[future], exc)

    # ── Compute verdict ───────────────────────────────────────────────────────
    vt      = ip_intel.get("virustotal", {})
    abuse   = ip_intel.get("abuseipdb", {})
    otx     = ip_intel.get("otx", {})

    vt_malicious   = vt.get("malicious", 0) or 0
    abuse_score    = abuse.get("abuse_confidence_score", 0) or 0
    otx_pulses     = otx.get("pulse_count", 0) or 0

    if vt_malicious >= 5 or abuse_score >= 80:
        verdict = "MALICIOUS"
    elif vt_malicious >= 1 or abuse_score >= 25 or otx_pulses >= 3:
        verdict = "SUSPICIOUS"
    elif (vt.get("reputation", 0) or 0) > 0:
        verdict = "LEGITIMATE_SERVICE"
    elif ip_intel["sources"]:
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN (no API keys configured)"

    ip_intel["verdict"]      = verdict
    ip_intel["abuse_score"]  = abuse_score
    ip_intel["vt_malicious"] = vt_malicious
    ip_intel["otx_pulses"]   = otx_pulses
    results["source"]        = "direct_parallel"
    results["ip_intel"]      = ip_intel
    results["verdict"]       = verdict
    # Write-through cache to threat_intel_cache
    try:
        import uuid as _uuid2
        from datetime import timedelta
        from ai_agents.database.db_manager import get_db
        from ai_agents.database.models import ThreatIntelCache
        ioc_val = ip or file_hash or domain or ""
        ioc_t   = "ip" if ip else ("hash" if file_hash else "domain")
        with get_db() as db:
            existing = db.query(ThreatIntelCache).filter(
                ThreatIntelCache.ioc_value == ioc_val
            ).first()
            if existing:
                existing.threat_data = results
                existing.expires_at  = datetime.utcnow() + timedelta(hours=24)
            else:
                db.add(ThreatIntelCache(
                    id         = str(_uuid2.uuid4()),
                    ioc_type   = ioc_t,
                    ioc_value  = ioc_val,
                    threat_data= results,
                    source     = "enrich_ioc",
                    expires_at = datetime.utcnow() + timedelta(hours=24),
                ))
            db.commit()
    except Exception as _ie:
        logger.debug("threat_intel_cache_write_failed: %s", _ie)
    # Build formatted verdict card
    ip = results.get("ip") or results.get("domain") or results.get("file_hash","IOC")
    sources_summary = []
    if ip_intel.get("vt_malicious",0) > 0:
        sources_summary.append(f"VirusTotal: {ip_intel['vt_malicious']} malicious detections")
    if ip_intel.get("abuse_score",0) > 0:
        sources_summary.append(f"AbuseIPDB: confidence {ip_intel['abuse_score']}%")
    if ip_intel.get("otx_pulses",0) > 0:
        sources_summary.append(f"OTX: {ip_intel['otx_pulses']} threat pulses")
    verdict_icon = {"MALICIOUS":"🔴","SUSPICIOUS":"🟡","LEGITIMATE_SERVICE":"🟢","CLEAN":"🟢","UNKNOWN":"⚪"}.get(verdict,"⚪")
    results["formatted"] = (
        f"**{verdict_icon} {verdict}** — `{ip}`\n"
        + ("\n".join(f"- {s}" for s in sources_summary) if sources_summary else "- No threat intelligence found")
    )
    return results



def query_knowledge_base(
    query_type: str,
    search_term: Optional[str] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """Query the local PostgreSQL knowledge base for cached security data.
    Use this when APIs are unavailable, or to look up previously seen data.
    query_type options:
      - 'cve': look up CVE details by ID or keyword (e.g. 'CVE-2026-46243', 'openssl')
      - 'ioc': look up threat intel verdict for an IP/hash/domain (e.g. '185.220.101.42') — ONLY for malicious/clean verdict
      - 'correlations': look up PAST ATTACK HISTORY — use this for "have we seen attacks from X", "history of IP X", "prior incidents from X"
    IMPORTANT: For questions about attack history, past incidents, or prior activity from an IP → ALWAYS use query_type='correlations', NOT 'ioc'.
    search_term: CVE ID, IP address, package name, or keyword to search for.
    limit: max results to return (default 10).
    """
    from ai_agents.database.db_manager import get_db
    from ai_agents.database.models import CVERecord, ThreatIntelCache, CorrelatedIncident
    try:
        with get_db() as db:
            if query_type == "cve":
                q = db.query(CVERecord)
                if search_term:
                    if search_term.upper().startswith("CVE-"):
                        q = q.filter(CVERecord.cve_id == search_term.upper())
                    else:
                        q = q.filter(CVERecord.description.ilike(f"%{search_term}%"))
                rows = q.limit(limit).all()
                results = [{
                    "cve_id":      r.cve_id,
                    "severity":    r.severity or "Unrated",
                    "cvss_score":  r.cvss_score if r.cvss_score and r.cvss_score > 0 else None,
                    "description": r.description or "—",
                    "packages":    r.affected_products or [],
                } for r in rows]
                if not results:
                    return {"found": False, "message": f"No cached data for '{search_term}'", "formatted": f"No cached CVE data found for '{search_term}'. Try running get_agent_vulnerabilities first to populate the cache."}

                # Enrich short descriptions from NVD API
                import os as _os_nvd, requests as _req_nvd
                _nvd_key = _os_nvd.getenv("NVD_API_KEY","")
                _nvd_url = _os_nvd.getenv("NVD_API_BASE_URL","https://services.nvd.nist.gov/rest/json/cves/2.0")
                for _r in results:
                    _desc = _r.get("description","")
                    _cid  = _r.get("cve_id","")
                    if _cid and _cid.startswith("CVE-") and (not _desc or len(_desc) < 150):
                        try:
                            _nvd_resp = _req_nvd.get(
                                _nvd_url,
                                params={"cveId": _cid},
                                headers={"apiKey": _nvd_key} if _nvd_key else {},
                                timeout=8
                            )
                            if _nvd_resp.status_code == 200:
                                _nvd_data = _nvd_resp.json()
                                _nvd_vulns = _nvd_data.get("vulnerabilities",[])
                                if _nvd_vulns:
                                    _nvd_descs = _nvd_vulns[0].get("cve",{}).get("descriptions",[])
                                    _en_desc = next((d["value"] for d in _nvd_descs if d.get("lang")=="en"), None)
                                    if _en_desc:
                                        _r["description"] = _en_desc
                                        # Update cache
                                        try:
                                            _existing = db.query(CVERecord).filter(CVERecord.cve_id==_cid).first()
                                            if _existing:
                                                _existing.description = _en_desc
                                                db.commit()
                                        except Exception: pass
                        except Exception as _nvd_e:
                            logger.debug("nvd_enrich_failed: %s", _nvd_e)

                lines = [f"**CVE Cache** — {len(results)} result(s) for '{search_term}'\n"]
                for r in results:
                    cvss = str(r["cvss_score"]) if r["cvss_score"] else "N/A"
                    lines.append(f"**{r['cve_id']}** — {r['severity']} | CVSS {cvss}")
                    lines.append(f"  {r.get('description') or '—'}")
                    lines.append("")
                return {"found": True, "results": results, "formatted": "\n".join(lines)}

            elif query_type == "ioc":
                q = db.query(ThreatIntelCache)
                if search_term:
                    q = q.filter(ThreatIntelCache.ioc_value == search_term)
                rows = q.order_by(ThreatIntelCache.created_at.desc()).limit(limit).all()
                results = [{
                    "ioc_type":   r.ioc_type,
                    "ioc_value":  r.ioc_value,
                    "verdict":    (r.threat_data or {}).get("verdict","UNKNOWN"),
                    "threat_data": r.threat_data,
                    "cached_at":  r.created_at.isoformat() if r.created_at else None,
                } for r in rows]
                if not results:
                    return {"found": False, "message": f"No cached threat intel for '{search_term}'", "formatted": f"No cached IOC data for '{search_term}'. Try enrich_ioc first."}
                r = results[0]
                verdict = r["verdict"]
                icon = {"MALICIOUS":"🔴","SUSPICIOUS":"🟡","CLEAN":"🟢","LEGITIMATE_SERVICE":"🟢"}.get(verdict,"⚪")
                fmt = f"**{icon} {verdict}** — `{r['ioc_value']}` (cached {(r['cached_at'] or '')[:10]})"
                return {"found": True, "results": results, "formatted": fmt}

            elif query_type == "correlations":
                q = db.query(CorrelatedIncident)
                if search_term:
                    q = q.filter(
                        (CorrelatedIncident.shared_ip == search_term) |
                        (CorrelatedIncident.mitre_technique_id.ilike(f"%{search_term}%")) |
                        (CorrelatedIncident.attack_narrative.ilike(f"%{search_term}%"))
                    )
                rows = q.order_by(CorrelatedIncident.created_at.desc()).limit(limit).all()
                results = [{
                    "id":               r.id,
                    "attacker_ip":      r.shared_ip,
                    "severity":         r.combined_severity,
                    "mitre_technique":  r.mitre_technique_id,
                    "technique_name":   r.mitre_technique_name,
                    "narrative":        r.attack_narrative,
                    "playbook":         r.ansible_playbook,
                    "created_at":       r.created_at.isoformat() if r.created_at else None,
                } for r in rows]
                if not results:
                    return {"found": False, "message": f"No past correlations for '{search_term}'", "formatted": f"No past correlation records found for '{search_term}'."}
                lines = [f"**Past Correlations** — {len(results)} record(s) for '{search_term}'\n"]
                for r in results:
                    ts = (r["created_at"] or "")[:16].replace("T"," ")
                    lines.append(f"- **{r['attacker_ip'] or '?'}** | {r['mitre_technique'] or '?'} ({r['technique_name'] or '?'}) | {ts} UTC")
                    if r["narrative"]:
                        lines.append(f"  {r['narrative'][:150]}")
                return {"found": True, "results": results, "formatted": "\n".join(lines)}

            else:
                return {"error": f"Unknown query_type '{query_type}'. Use: cve, ioc, correlations"}

    except Exception as exc:
        logger.warning("agent_tools.query_knowledge_base.failed: %s", exc)
        return {"error": str(exc)}

TOOLS: Dict[str, Any] = {
    "search_alerts": search_alerts,
    "count_alerts": count_alerts,
    "top_signatures": top_signatures,
    "list_agents": list_agents,
    "get_alert": get_alert,
    "get_incidents": get_incidents,
    "get_incident_details": get_incident_details,
    "search_archives": search_archives,
    "agent_inventory":          agent_inventory,
    # ── Phase 3 additions ─────────────────────────────────────────────
    "get_agent_details":         get_agent_details,
    "get_agent_vulnerabilities": get_agent_vulnerabilities,
    "query_knowledge_base":     query_knowledge_base,
    "get_wazuh_rule":            get_wazuh_rule,
    "get_fim_events":            get_fim_events,
    "execute_playbook":          execute_playbook,
    "get_active_blocks":         get_active_blocks,
    "get_sca_results":           get_sca_results,
    "gather_alert_context":      gather_alert_context,
    "enrich_ioc":                 enrich_ioc,
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
    # Ambiguous natural language — must come before the regex
    _NATURAL = {
        "weeks": "30d",   # ambiguous plural → max 1 month
        "month": "30d",
        "months": "30d",
        "last month": "30d",
        "all": "30d",
        "everything": "30d",
    }
    if s in _NATURAL:
        return _NATURAL[s]

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
    # Phase 3 additions
    "get_agent_vulnerabilities": _coerce_search_alerts_args,
    "get_fim_events":            _coerce_search_alerts_args,
    "get_active_blocks":         _coerce_search_alerts_args,
    "get_sca_results":           _coerce_search_alerts_args,
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
