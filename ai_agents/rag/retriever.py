"""
Multi-source RAG Retriever for SENTINEL-AI Commander.

Key improvements over v1:
  - Time window parsed from natural language ("last 30 minutes", "last week")
  - Keyword/text search in rule.description + full_log (catches "nmap", "brute force", etc.)
  - Expanded attack_intent regex
  - Context budget: hard cap of 20 docs per source (prevents context flooding)
  - Suricata filtered by query terms, not just "return all"
  - Archives skipped unless query explicitly mentions pfSense / syslog / archive
"""
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from ai_agents.tools.wazuh_client import WazuhClient, WazuhAPIError
from ai_agents.tools.suricata_client import SuricataClient
from ai_agents.integrations.redis_manager import get_redis
from ai_agents.database.db_manager import get_db
from ai_agents.database.models import Incident, CorrelatedIncident, AgentActivity

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

# Hard cap: total docs sent to LLM context.
# 800 was the old value — this caused the LLM to miss relevant docs buried deep.
# New value: 20 per source max, 120 total across all sources.
MAX_PER_SOURCE = 20
MAX_TOTAL = 120

# Expanded attack intent keywords — now catches nmap, port scan, recon, activity, etc.
ATTACK_INTENT_PATTERN = re.compile(
    r'\b('
    r'attack|attacks|exploit|exploitation|intrusion|'
    r'scan|scanning|nmap|nikto|masscan|zmap|'
    r'brute.?force|brute|password.*attempt|credential|'
    r'malicious|threat|suspicious|anomal|'
    r'ids|nids|suricata|'
    r'recon|reconnaissance|enumerat|'
    r'lateral|pivot|escalat|privilege|'
    r'malware|trojan|backdoor|shell|payload|'
    r'inject|xss|sqli|sql.*injection|'
    r'activity|activities|incident|event|alert|'
    r'failed|failure|denied|blocked|drop|'
    r'unusual|unexpected|abnormal'
    r')\b',
    re.IGNORECASE
)

# FIM / syscheck intent — queries about file changes
FIM_INTENT_PATTERN = re.compile(
    r'\b(file|fim|integrity|syscheck|created|deleted|modified|changed|'
    r'added|removed|permission|chmod|chown|tamper)\b',
    re.IGNORECASE
)

# Archive intent — only query archives when specifically asked
ARCHIVE_INTENT_PATTERN = re.compile(
    r'\b(pfsense|pfSense|syslog|firewall|archive|raw|full.?log|filter.?log)\b',
    re.IGNORECASE
)

# Stopwords for keyword extraction
STOPWORDS = {
    "show", "any", "the", "are", "were", "from", "that", "have", "been",
    "there", "with", "about", "what", "which", "does", "events", "logs",
    "contain", "recent", "all", "give", "list", "find", "search", "get",
    "can", "you", "me", "this", "for", "not", "has", "was", "will", "how",
    "who", "address", "please", "tell", "last", "hour", "hours", "day",
    "days", "mean", "could", "would", "should", "detected", "alerts", "alert",
    "attacks", "attack", "minute", "minutes", "week", "weeks", "today",
    "yesterday", "ago", "past", "recent", "latest", "new", "between",
    "and", "the", "its", "also", "just", "only", "more", "less",
}


def _parse_time_window(query: str) -> str:
    """
    Extract time window from natural language query.
    Returns an OpenSearch relative date math string.

    Examples:
      "last 30 minutes"  → "now-30m"
      "last 2 hours"     → "now-2h"
      "last 24h"         → "now-24h"
      "last week"        → "now-7d"
      "today"            → "now/d"   (start of today)
      (no time mention)  → "now-24h" (default)
    """
    q = query.lower()

    # Explicit minute ranges: "last 30 minutes", "past 15 min"
    m = re.search(r'(?:last|past)\s+(\d+)\s*min', q)
    if m:
        return f"now-{m.group(1)}m"

    # Explicit hour ranges: "last 2 hours", "last 6h"
    m = re.search(r'(?:last|past)\s+(\d+)\s*h', q)
    if m:
        return f"now-{m.group(1)}h"

    # "last hour" / "past hour"
    if re.search(r'(?:last|past)\s+hour\b', q):
        return "now-1h"

    # Explicit day ranges: "last 3 days", "last 7d"
    m = re.search(r'(?:last|past)\s+(\d+)\s*d', q)
    if m:
        n = int(m.group(1))
        return f"now-{n}d"

    # "last week" / "past week"
    if re.search(r'(?:last|past)\s+week\b', q):
        return "now-7d"

    # "last month"
    if re.search(r'(?:last|past)\s+month\b', q):
        return "now-30d"

    # "today"
    if re.search(r'\btoday\b', q):
        return "now/d"

    # "yesterday"
    if re.search(r'\byesterday\b', q):
        return "now-1d/d"

    # Default: 24 hours
    return "now-24h"


def _extract_query_tokens(query: str, known_agent_names: set, known_ips: list) -> Dict:
    """
    Parse the query into structured search tokens.
    Returns dict with: ips, agent_names, mitre_ids, keywords, time_window,
                       attack_intent, fim_intent, archive_intent
    """
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
    mitre_ids = re.findall(r'T\d{4}(?:\.\d{3})?', query, re.IGNORECASE)

    # Agent name detection — match against known agents, case-insensitive
    agent_names = []
    query_lower = query.lower()
    for token in re.findall(r'[\w-]+', query):
        if token.lower() in known_agent_names and token.lower() not in STOPWORDS:
            agent_names.append(token)

    # Also detect agent name patterns: "kali-agent-1", "ubuntu-agent-2", etc.
    agent_pattern = re.findall(
        r'\b(kali[-_]agent[-_]\d+|ubuntu[-_]agent[-_]\d+|rhel[-_]agent[-_]\d+|'
        r'victim\d*[-_]?\w*|auto[-_]\d+[-_]\w+)\b',
        query, re.IGNORECASE
    )
    agent_names.extend([a for a in agent_pattern if a.lower() in known_agent_names])
    agent_names = list(set(agent_names))  # dedup

    # Keywords for full-text search (what remains after removing structured tokens)
    excluded = set(ips) | {m.lower() for m in mitre_ids} | {a.lower() for a in agent_names} | STOPWORDS
    keywords = [
        w for w in re.findall(r'[\w.-]+', query)
        if len(w) > 2
        and w.lower() not in excluded
        and not re.match(r'^\d+$', w)  # skip pure numbers
    ]

    return {
        "ips": ips,
        "agent_names": agent_names,
        "mitre_ids": mitre_ids,
        "keywords": keywords,
        "time_window": _parse_time_window(query),
        "attack_intent": bool(ATTACK_INTENT_PATTERN.search(query)),
        "fim_intent": bool(FIM_INTENT_PATTERN.search(query)),
        "archive_intent": bool(ARCHIVE_INTENT_PATTERN.search(query)),
    }


def _build_opensearch_body(tokens: Dict, limit: int, index_time_field: str = "timestamp") -> Dict:
    """
    Build a focused OpenSearch query from parsed tokens.
    This is the core fix: adds keyword search in rule.description + full_log.
    """
    must = [{"range": {index_time_field: {"gte": tokens["time_window"]}}}]
    must_not = []

    # Agent name filter — MUST
    if tokens["agent_names"]:
        must.append({"bool": {"should": [
            {"match_phrase": {"agent.name": an}} for an in tokens["agent_names"]
        ], "minimum_should_match": 1}})

    # IP filter — MUST
    if tokens["ips"]:
        ip_clauses = []
        for ip in tokens["ips"]:
            for field in ["data.srcip", "data.dstip", "agent.ip", "full_log"]:
                ip_clauses.append({"match_phrase": {field: ip}})
        must.append({"bool": {"should": ip_clauses, "minimum_should_match": 1}})

    # MITRE technique — MUST
    for tid in tokens["mitre_ids"]:
        must.append({"match_phrase": {"rule.mitre.id": tid}})

    # Attack group filter — applied when attack_intent is detected
    if tokens["attack_intent"] and not tokens["fim_intent"]:
        must.append({"bool": {"should": [
            {"match": {"rule.groups": "suricata"}},
            {"match": {"rule.groups": "ids"}},
            {"match": {"rule.groups": "attack"}},
            {"match": {"rule.groups": "web_scan"}},
            {"match": {"rule.groups": "recon"}},
            {"match": {"rule.groups": "authentication_failed"}},
            {"match": {"rule.groups": "authentication_failures"}},
            {"match": {"rule.groups": "invalid_login"}},
            {"match": {"rule.groups": "sql_injection"}},
            {"match": {"rule.groups": "command_injection"}},
            {"match": {"rule.groups": "web_attack"}},
            {"match": {"rule.groups": "exploit_attempt"}},
            {"match": {"rule.groups": "malware"}},
            {"match": {"rule.groups": "rootkit"}},
            {"match": {"rule.groups": "nmap"}},
            {"range": {"rule.level": {"gte": 5}}},
        ], "minimum_should_match": 1}})
        must_not.extend([
            {"match": {"rule.groups": "authentication_success"}},
            {"match": {"rule.groups": "pam"}},
        ])

    # FIM filter
    if tokens["fim_intent"]:
        must.append({"bool": {"should": [
            {"match": {"rule.groups": "syscheck"}},
            {"match": {"rule.groups": "ossec"}},
            {"match_phrase": {"rule.description": "integrity"}},
            {"match_phrase": {"rule.description": "file"}},
        ], "minimum_should_match": 1}})

    # ── KEY FIX: Keyword search in rule description + full_log ────────────
    # This is what was missing before — nmap/brute force/etc were never
    # matched against the actual text content of alerts.
    if tokens["keywords"]:
        keyword_clauses = []
        for kw in tokens["keywords"][:8]:  # cap at 8 keywords to avoid query explosion
            keyword_clauses.append({"multi_match": {
                "query": kw,
                "fields": [
                    "rule.description^3",     # description gets highest weight
                    "rule.groups^2",
                    "full_log",
                    "agent.name",
                    "data.srcip",
                    "data.dstip",
                ],
                "type": "best_fields",
                "fuzziness": "AUTO",          # handles typos: "namp" → "nmap"
            }})

        if tokens["ips"] or tokens["agent_names"] or tokens["mitre_ids"]:
            # When we have hard filters, keywords become a SHOULD (bonus relevance)
            # rather than MUST, so we don't accidentally filter out relevant alerts
            # that lack the keyword in description
            pass  # keywords added as should below
        else:
            # No hard filters — keyword match is required
            must.append({"bool": {
                "should": keyword_clauses,
                "minimum_should_match": 1,
            }})

    body = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
    }
    if must_not:
        body["query"]["bool"]["must_not"] = must_not

    # Add keyword as should (relevance booster) even when other filters exist
    if tokens["keywords"] and (tokens["ips"] or tokens["agent_names"]):
        keyword_clauses = []
        for kw in tokens["keywords"][:8]:
            keyword_clauses.append({"multi_match": {
                "query": kw,
                "fields": ["rule.description^3", "rule.groups^2", "full_log"],
            }})
        body["query"]["bool"]["should"] = keyword_clauses
        body["query"]["bool"]["boost"] = 1.5

    return body


class RAGRetriever:
    """Retrieves relevant security context from all SENTINEL data sources."""

    def __init__(self):
        self._wazuh = WazuhClient()
        self._suricata = SuricataClient(mode="file")
        self._redis = get_redis()
        self._agent_name_cache: Optional[set] = None

    def _get_known_agent_names(self) -> set:
        """Cache agent names for the lifetime of this retriever instance."""
        if self._agent_name_cache is None:
            try:
                agents = self._wazuh.get_agents()
                self._agent_name_cache = {a.get("name", "").lower() for a in agents if a.get("name")}
            except Exception:
                self._agent_name_cache = set()
        return self._agent_name_cache

    def retrieve(self, query: str, top_k: int = MAX_PER_SOURCE) -> Dict[str, Any]:
        """
        Retrieve focused, relevant context for the given query.

        Context budget is hard-capped to prevent flooding the LLM:
          - wazuh_alerts:   max 20  (primary alert data)
          - archives:       max 10  (only if archive_intent detected)
          - monitoring:     max 5   (agent status)
          - statistics:     max 3   (counts/aggregates)
          - incidents:      max 10  (PostgreSQL incidents)
          - correlated:     max 10  (cross-source incidents)
          - suricata_alerts: max 15 (filtered by query)
          - agent_activity: max 5

        Total max: ~78 docs — well within Groq's effective attention window.
        """
        per_source = min(top_k, MAX_PER_SOURCE)

        # Parse query once, share tokens across all searches
        known_agents = self._get_known_agent_names()
        tokens = _extract_query_tokens(query, known_agents, [])

        logger.debug(
            "retriever.tokens query=%r tokens=%s",
            query[:80], {k: v for k, v in tokens.items() if v}
        )

        context = {
            "wazuh_alerts": self._search_wazuh(tokens, per_source),
            "archives": self._search_archives(tokens, 10) if tokens["archive_intent"] else [],
            "monitoring": self._search_monitoring(5),
            "statistics": [],  # skip heavy stats query for speed
            "incidents": self._search_incidents(tokens, 10),
            "correlated": self._search_correlated(tokens, 10),
            "suricata_alerts": self._search_suricata(tokens, 15),
            "agent_activity": self._search_agent_activity(5),
            "stats": self._get_stats(),
        }

        # Log what we found for debugging
        total = sum(len(v) for v in context.values() if isinstance(v, list))
        logger.info(
            "retriever.done query=%r time=%s agents=%s ips=%s kw=%s "
            "alerts=%d suricata=%d archives=%d total=%d",
            query[:60], tokens["time_window"],
            tokens["agent_names"], tokens["ips"], tokens["keywords"][:3],
            len(context["wazuh_alerts"]), len(context["suricata_alerts"]),
            len(context["archives"]), total,
        )
        return context

    def _search_wazuh(self, tokens: Dict, limit: int) -> List[Dict]:
        """Search Wazuh alerts index with full keyword + filter support."""
        try:
            body = _build_opensearch_body(tokens, limit, index_time_field="timestamp")

            data = self._wazuh._indexer_request(
                "POST", "/wazuh-alerts-4.x-*/_search",
                json=body,
                headers={"Content-Type": "application/json"},
            )
            hits = data.get("hits", {}).get("hits", [])
            return [
                {
                    "_doc_id": h.get("_id", ""),
                    "_doc_index": h.get("_index", ""),
                    "timestamp": h["_source"].get("timestamp"),
                    "rule_id": h["_source"].get("rule", {}).get("id"),
                    "rule_level": h["_source"].get("rule", {}).get("level"),
                    "rule_description": h["_source"].get("rule", {}).get("description"),
                    "rule_groups": h["_source"].get("rule", {}).get("groups", []),
                    "agent_name": h["_source"].get("agent", {}).get("name"),
                    "agent_ip": h["_source"].get("agent", {}).get("ip"),
                    "src_ip": h["_source"].get("data", {}).get("srcip"),
                    "dst_ip": h["_source"].get("data", {}).get("dstip"),
                    "mitre": h["_source"].get("rule", {}).get("mitre", {}),
                    "full_log": (h["_source"].get("full_log", "") or "")[:200],
                }
                for h in hits
            ]
        except Exception as e:
            logger.warning("rag.wazuh_search_failed: %s", e)
            return []

    def _search_archives(self, tokens: Dict, limit: int) -> List[Dict]:
        """Search wazuh-archives — only called when archive intent detected."""
        try:
            # Use @timestamp for archives index
            body = _build_opensearch_body(tokens, limit, index_time_field="@timestamp")
            # Archives use @timestamp not timestamp
            body["sort"] = [{"@timestamp": {"order": "desc"}}]

            data = self._wazuh._indexer_request(
                "POST", "/wazuh-archives-4.x-*/_search",
                json=body,
                headers={"Content-Type": "application/json"},
            )
            hits = data.get("hits", {}).get("hits", [])
            return [
                {
                    "_doc_id": h.get("_id", ""),
                    "_doc_index": h.get("_index", ""),
                    "timestamp": h["_source"].get("@timestamp") or h["_source"].get("timestamp"),
                    "location": h["_source"].get("location"),
                    "agent_name": h["_source"].get("agent", {}).get("name"),
                    "full_log": (h["_source"].get("full_log", "") or "")[:300],
                    "decoder": h["_source"].get("decoder", {}).get("name", ""),
                    "rule_description": h["_source"].get("rule", {}).get("description", ""),
                    "rule_level": h["_source"].get("rule", {}).get("level"),
                }
                for h in hits
            ]
        except Exception as e:
            logger.warning("rag.archives_search_failed: %s", e)
            return []

    def _search_monitoring(self, limit: int) -> List[Dict]:
        """Agent connection status — always return latest regardless of query."""
        try:
            data = self._wazuh._indexer_request(
                "POST", "/wazuh-monitoring-*/_search",
                json={
                    "size": limit,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "query": {"range": {"timestamp": {"gte": "now-2h"}}},
                },
                headers={"Content-Type": "application/json"},
            )
            results = [h.get("_source", {}) for h in data.get("hits", {}).get("hits", [])]
        except Exception as e:
            logger.warning("rag.monitoring_failed: %s", e)
            results = []
        return [
            {
                "timestamp": r.get("timestamp"),
                "agent_id": r.get("id"),
                "agent_name": r.get("name"),
                "agent_ip": r.get("ip"),
                "status": r.get("status"),
                "os_name": r.get("os", {}).get("name", ""),
            }
            for r in results
        ]

    def _search_incidents(self, tokens: Dict, limit: int) -> List[Dict]:
        """Search PostgreSQL incidents — filtered by keywords and IPs."""
        try:
            with get_db() as db:
                q = db.query(Incident).order_by(Incident.created_at.desc())

                # Filter by IP if present
                for ip in tokens["ips"]:
                    q = q.filter(Incident.source_ip == ip)

                # Filter by keywords (first 3 meaningful ones)
                kw = [k for k in tokens["keywords"] if len(k) > 3][:3]
                for word in kw:
                    q = q.filter(
                        Incident.rule_description.ilike(f"%{word}%")
                        | Incident.analysis.ilike(f"%{word}%")
                        | Incident.source_ip.ilike(f"%{word}%")
                    )

                rows = q.limit(limit).all()
                return [
                    {
                        "id": r.id,
                        "severity": r.severity,
                        "status": r.status,
                        "rule_description": r.rule_description,
                        "source_ip": r.source_ip,
                        "mitre_techniques": r.mitre_techniques,
                        "analysis": (r.analysis or "")[:400],
                        "confidence_score": r.confidence_score,
                        "playbook_executed": r.playbook_executed,
                        "created_at": str(r.created_at),
                    }
                    for r in rows
                ]
        except Exception as e:
            logger.warning("rag.incident_search_failed: %s", e)
            return []

    def _search_correlated(self, tokens: Dict, limit: int) -> List[Dict]:
        """Correlated incidents filtered by IP if present."""
        try:
            with get_db() as db:
                q = db.query(CorrelatedIncident).order_by(CorrelatedIncident.created_at.desc())
                for ip in tokens["ips"]:
                    q = q.filter(CorrelatedIncident.shared_ip == ip)
                rows = q.limit(limit).all()
                return [
                    {
                        "id": r.id,
                        "wazuh_rule": r.wazuh_rule,
                        "suricata_signature": r.suricata_signature,
                        "combined_severity": r.combined_severity,
                        "mitre_tactic": r.mitre_tactic,
                        "mitre_technique_id": r.mitre_technique_id,
                        "shared_ip": r.shared_ip,
                        "attack_narrative": (r.attack_narrative or "")[:300],
                        "ansible_playbook": r.ansible_playbook,
                        "created_at": str(r.created_at),
                    }
                    for r in rows
                ]
        except Exception as e:
            logger.warning("rag.correlated_search_failed: %s", e)
            return []

    def _search_suricata(self, tokens: Dict, limit: int) -> List[Dict]:
        """
        Read Suricata eve.json — filtered by IPs and keywords.
        Previously returned ALL recent events regardless of query.
        """
        try:
            events = self._suricata.read_recent_from_file(last_n_lines=5000)
            filtered = []
            for evt in events:
                # Always include if we have no filters
                if not tokens["ips"] and not tokens["keywords"] and not tokens["agent_names"]:
                    filtered.append(evt.to_dict())
                    if len(filtered) >= limit:
                        break
                    continue

                # Filter by IP
                if tokens["ips"]:
                    if any(
                        ip in (evt.src_ip or "") or ip in (evt.dest_ip or "")
                        for ip in tokens["ips"]
                    ):
                        filtered.append(evt.to_dict())
                        if len(filtered) >= limit:
                            break
                        continue

                # Filter by keyword in signature
                sig = (evt.signature or "").lower()
                if any(kw.lower() in sig for kw in tokens["keywords"]):
                    filtered.append(evt.to_dict())
                    if len(filtered) >= limit:
                        break

            return filtered
        except Exception as e:
            logger.warning("rag.suricata_search_failed: %s", e)
            return []

    def _search_agent_activity(self, limit: int) -> List[Dict]:
        try:
            with get_db() as db:
                rows = (
                    db.query(AgentActivity)
                    .order_by(AgentActivity.created_at.desc())
                    .limit(limit)
                    .all()
                )
                return [
                    {
                        "agent_name": r.agent_name,
                        "action": r.action,
                        "success": r.success,
                        "duration_ms": r.duration_ms,
                        "created_at": str(r.created_at),
                    }
                    for r in rows
                ]
        except Exception:
            return []

    def _get_stats(self) -> Dict:
        """Lightweight stats — alert counts by agent and level."""
        stats: Dict[str, Any] = {"wazuh_alerts": {}, "db_incidents": {}}
        try:
            body = {
                "size": 0,
                "aggs": {
                    "by_agent": {"terms": {"field": "agent.name", "size": 20}},
                    "by_level": {"terms": {"field": "rule.level", "size": 16}},
                },
                "query": {"range": {"timestamp": {"gte": "now-24h"}}},
            }
            data = self._wazuh._indexer_request(
                "POST", "/wazuh-alerts-4.x-*/_search",
                json=body,
                headers={"Content-Type": "application/json"},
            )
            total = data.get("hits", {}).get("total", {}).get("value", 0)
            by_level = {
                str(b["key"]): b["doc_count"]
                for b in data.get("aggregations", {}).get("by_level", {}).get("buckets", [])
            }
            by_agent = {
                b["key"]: b["doc_count"]
                for b in data.get("aggregations", {}).get("by_agent", {}).get("buckets", [])
            }

            critical = sum(v for k, v in by_level.items() if int(k) >= 13)
            high = sum(v for k, v in by_level.items() if 10 <= int(k) <= 12)
            medium = sum(v for k, v in by_level.items() if 7 <= int(k) <= 9)
            low = sum(v for k, v in by_level.items() if int(k) < 7)

            stats["wazuh_alerts"] = {
                "total": total,
                "by_severity": {"critical": critical, "high": high, "medium": medium, "low": low},
                "by_agent": by_agent,
            }
        except Exception as e:
            logger.warning("rag.stats_failed: %s", e)

        try:
            with get_db() as db:
                total_inc = db.query(Incident).count()
                by_sev = {
                    s: db.query(Incident).filter(Incident.severity == s).count()
                    for s in ["low", "medium", "high", "critical"]
                }
                stats["db_incidents"] = {"total": total_inc, "by_severity": by_sev}
        except Exception:
            pass

        return stats
