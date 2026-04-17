"""
Multi-source RAG Retriever for SENTINEL-AI Commander.

Retrieves context from:
  1. OpenSearch (Wazuh alerts index: wazuh-alerts-*)
  2. PostgreSQL (incidents, correlated_incidents, agent_activity)
  3. Suricata eve.json (recent IDS/IPS alerts)
  4. Redis cache (recent enrichment data)

PhD Contribution: Demonstrates context-aware retrieval across heterogeneous
security data sources for LLM-augmented SOC decision support.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ai_agents.tools.wazuh_client import WazuhClient, WazuhAPIError
from ai_agents.tools.suricata_client import SuricataClient
from ai_agents.integrations.redis_manager import get_redis
from ai_agents.database.db_manager import get_db
from ai_agents.database.models import Incident, CorrelatedIncident, AgentActivity

logger = logging.getLogger(__name__)


class RAGRetriever:
    """Retrieves relevant security context from all SENTINEL data sources."""

    def __init__(self):
        self._wazuh = WazuhClient()
        self._suricata = SuricataClient(mode="file")
        self._redis = get_redis()

    def retrieve(self, query: str, top_k: int = 100) -> Dict[str, Any]:
        """
        Retrieve context relevant to a natural language query.

        Returns a dict with keys: wazuh_alerts, incidents, correlated,
        suricata_alerts, agent_activity, stats — each containing
        the most relevant data for the query.
        """
        context = {
            "wazuh_alerts": [],
            "archives": [],
            "monitoring": [],
            "statistics": [],
            "incidents": [],
            "correlated": [],
            "suricata_alerts": [],
            "agent_activity": [],
            "stats": {},
        }

        # 1. OpenSearch — Wazuh alerts (primary security data)
        context["wazuh_alerts"] = self._search_wazuh(query, top_k)

        # 2. Archives — ALL raw events incl. pfSense syslog (largest source)
        context["archives"] = self._search_archives(query, top_k * 3)

        # 3. Monitoring — agent status (small dataset, fewer needed)
        context["monitoring"] = self._search_monitoring(query, min(top_k, 5))

        # 4. Statistics — manager metrics (few needed for context)
        context["statistics"] = self._search_statistics(query, min(top_k, 3))

        # 5. PostgreSQL — incidents
        context["incidents"] = self._search_incidents(query, top_k)

        # 3. PostgreSQL — correlated incidents
        context["correlated"] = self._search_correlated(query, top_k)

        # 4. Suricata — recent IDS alerts
        context["suricata_alerts"] = self._search_suricata(query, top_k)

        # 5. Agent activity log
        context["agent_activity"] = self._search_agent_activity(top_k)

        # 6. Statistics
        context["stats"] = self._get_stats()

        return context

    def _search_wazuh(self, query: str, limit: int) -> List[Dict]:
        """Fetch recent Wazuh alerts from OpenSearch with doc IDs."""
        try:
            import re
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
            technique_ids = re.findall(r'T\d{4}(?:\.\d{3})?', query, re.IGNORECASE)

            # Detect agent names
            agent_names = []
            try:
                agents = self._wazuh.get_agents()
                known_names = {a.get("name", "").lower() for a in agents if a.get("name")}
                for token in re.findall(r'[\w-]+', query):
                    if token.lower() in known_names:
                        agent_names.append(token)
            except Exception:
                pass

            # Attack intent
            attack_intent = bool(re.search(
                r'\b(attack|attacks|exploit|intrusion|scan|brute.?force|malicious|threat|suspicious|ids|nids)\b',
                query, re.IGNORECASE))

            body = {
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": [{"range": {"timestamp": {"gte": "now-24h"}}}]}},
            }

            # Agent names — MUST match
            if agent_names:
                an_should = []
                for an in agent_names:
                    an_should.append({"match_phrase": {"agent.name": an}})
                body["query"]["bool"]["must"].append({"bool": {"should": an_should, "minimum_should_match": 1}})

            # IPs — MUST match
            if ips:
                ip_should = []
                for ip in ips:
                    ip_should.append({"match_phrase": {"data.srcip": ip}})
                    ip_should.append({"match_phrase": {"data.dstip": ip}})
                    ip_should.append({"match_phrase": {"agent.ip": ip}})
                body["query"]["bool"]["must"].append({"bool": {"should": ip_should, "minimum_should_match": 1}})

            # MITRE technique IDs — MUST match
            for tid in technique_ids:
                body["query"]["bool"]["must"].append({"match_phrase": {"rule.mitre.id": tid}})

            # Attack intent — FILTER to actual attack-indicating alerts
            # MUST be in attack-related groups OR high severity, AND NOT a benign login
            if attack_intent:
                # At least one of these must be true
                body["query"]["bool"]["must"].append({"bool": {"should": [
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
                    {"range": {"rule.level": {"gte": 7}}},
                ], "minimum_should_match": 1}})
                # Exclude benign authentication success alerts
                body["query"]["bool"]["must_not"] = body["query"]["bool"].get("must_not", [])
                body["query"]["bool"]["must_not"].extend([
                    {"match": {"rule.groups": "authentication_success"}},
                    {"match": {"rule.groups": "pam"}},
                ])

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
                    "mitre": h["_source"].get("rule", {}).get("mitre", {}),
                }
                for h in hits
            ]
        except Exception as e:
            logger.warning("rag.wazuh_search_failed: %s", e)
            return []

    def _search_opensearch(self, index: str, query: str, limit: int) -> List[Dict]:
        """Generic OpenSearch search across any wazuh index."""
        import re
        try:
            # Extract IPs, technique IDs, and meaningful keywords
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
            technique_ids = re.findall(r'T\d{4}(?:\.\d{3})?', query, re.IGNORECASE)

            # Detect agent names — fetch current agents and match
            agent_names = []
            try:
                agents = self._wazuh.get_agents()
                known_names = {a.get("name", "").lower() for a in agents if a.get("name")}
                for token in re.findall(r'[\w-]+', query):
                    if token.lower() in known_names:
                        agent_names.append(token)
            except Exception:
                pass

            # Detect intent — "attack" semantics should bias to suricata/mitre-tagged
            attack_intent = bool(re.search(r'\b(attack|attacks|exploit|intrusion|scan|brute.?force|malicious|threat|suspicious|ids|nids)\b', query, re.IGNORECASE))

            stopwords = {
                "show", "any", "the", "are", "were", "from", "that", "have",
                "been", "there", "with", "about", "what", "which", "does",
                "events", "logs", "contain", "containing", "recent", "all",
                "give", "list", "find", "search", "get", "can", "you", "me",
                "this", "for", "not", "has", "was", "will", "how", "who",
                "address", "please", "tell", "last", "hour", "hours", "day",
                "days", "mean", "could", "would", "should", "detected",
                "alerts", "alert", "attacks", "attack",
            }
            # Exclude already-parsed agent names from keywords
            agent_lower = {a.lower() for a in agent_names}
            keywords = [w for w in re.findall(r'[\w.:-]+', query)
                        if len(w) > 2 and w.lower() not in stopwords
                        and w not in ips and w.lower() not in agent_lower]

            body = {
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"bool": {"must": [{"range": {"@timestamp": {"gte": "now-24h"}}}], "should": [], "minimum_should_match": 0}},
            }

            # Agent names — MUST match (required filter)
            if agent_names:
                an_should = []
                for an in agent_names:
                    an_should.append({"match_phrase": {"agent.name": an}})
                body["query"]["bool"]["must"].append({"bool": {"should": an_should, "minimum_should_match": 1}})

            # IP addresses — MUST match (required filter)
            if ips:
                ip_should = []
                for ip in ips:
                    ip_should.append({"match_phrase": {"full_log": ip}})
                    ip_should.append({"match_phrase": {"data.srcip": ip}})
                    ip_should.append({"match_phrase": {"data.dstip": ip}})
                    ip_should.append({"match_phrase": {"agent.ip": ip}})
                    ip_should.append({"match_phrase": {"location": ip}})
                body["query"]["bool"]["must"].append({"bool": {"should": ip_should, "minimum_should_match": 1}})

            # MITRE technique IDs — MUST match
            for tid in technique_ids:
                body["query"]["bool"]["must"].append({"match_phrase": {"rule.mitre.id": tid}})

            # Attack intent — FILTER (not just boost)
            if attack_intent:
                body["query"]["bool"]["must"].append({"bool": {"should": [
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
                    {"range": {"rule.level": {"gte": 7}}},
                ], "minimum_should_match": 1}})
                body["query"]["bool"]["must_not"] = body["query"]["bool"].get("must_not", [])
                body["query"]["bool"]["must_not"].extend([
                    {"match": {"rule.groups": "authentication_success"}},
                    {"match": {"rule.groups": "pam"}},
                ])

            # General keywords — when combined with IP/agent, also MUST match
            has_filter = bool(ips or agent_names or technique_ids)
            if keywords and has_filter:
                kw_should = []
                for kw in keywords:
                    kw_should.append({"multi_match": {"query": kw, "fields": ["full_log", "rule.description", "decoder.name", "location"]}})
                body["query"]["bool"]["must"].append({"bool": {"should": kw_should, "minimum_should_match": 1}})
            elif keywords:
                for kw in keywords:
                    body["query"]["bool"]["should"].append({"multi_match": {"query": kw, "fields": ["full_log", "rule.description", "decoder.name", "location"]}})
                if not attack_intent:
                    body["query"]["bool"]["minimum_should_match"] = 1

            # Fallback: only time filter → recent events from last 24h
            # (time filter already in "must", no need to replace)

            data = self._wazuh._indexer_request(
                "POST", f"/{index}/_search",
                json=body,
                headers={"Content-Type": "application/json"},
            )
            hits = data.get("hits", {}).get("hits", [])
            results = []
            for h in hits:
                doc = h.get("_source", {})
                doc["_doc_id"] = h.get("_id", "")
                doc["_doc_index"] = h.get("_index", "")
                results.append(doc)
            return results
        except Exception as e:
            logger.warning("rag.opensearch_search_failed index=%s: %s", index, e)
            return []

    def _search_archives(self, query: str, limit: int) -> List[Dict]:
        """Search wazuh-archives — ALL raw events including pfSense syslog."""
        results = self._search_opensearch("wazuh-archives-4.x-*", query, limit)
        # Preserve _doc_id and _doc_index from opensearch results
        # If keyword search returned nothing, fetch recent archives as baseline
        if not results:
            try:
                data = self._wazuh._indexer_request(
                    "POST", "/wazuh-archives-4.x-*/_search",
                    json={"size": limit, "sort": [{"@timestamp": {"order": "desc"}}], "query": {"range": {"@timestamp": {"gte": "now-24h"}}}},
                    headers={"Content-Type": "application/json"},
                )
                results = [h.get("_source", {}) for h in data.get("hits", {}).get("hits", [])]
            except Exception:
                pass
        return [
            {
                "_doc_id": r.get("_doc_id", ""),
                "_doc_index": r.get("_doc_index", ""),
                "timestamp": r.get("timestamp"),
                "location": r.get("location"),
                "agent_name": r.get("agent", {}).get("name"),
                "full_log": r.get("full_log", "")[:300],
                "decoder": r.get("decoder", {}).get("name", ""),
                "rule_description": r.get("rule", {}).get("description", ""),
                "rule_level": r.get("rule", {}).get("level"),
            }
            for r in results
        ]

    def _search_monitoring(self, query: str, limit: int) -> List[Dict]:
        """Search wazuh-monitoring — agent connection status history."""
        # Always fetch recent agent status — don't keyword filter
        try:
            data = self._wazuh._indexer_request(
                "POST", "/wazuh-monitoring-*/_search",
                json={"size": limit, "sort": [{"timestamp": {"order": "desc"}}], "query": {"range": {"timestamp": {"gte": "now-24h"}}}},
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
                "os_version": r.get("os", {}).get("version", ""),
                "node_name": r.get("node_name", ""),
            }
            for r in results
        ]

    def _search_statistics(self, query: str, limit: int) -> List[Dict]:
        """Search wazuh-statistics — manager performance and event metrics."""
        results = self._search_opensearch("wazuh-statistics-*", query, limit)
        return [
            {
                "timestamp": r.get("timestamp"),
                "total_events_decoded": r.get("analysisd", {}).get("total_events_decoded"),
                "syscheck_events_decoded": r.get("analysisd", {}).get("syscheck_events_decoded"),
                "alerts_written": r.get("analysisd", {}).get("alerts_written"),
                "firewall_written": r.get("analysisd", {}).get("firewall_written"),
                "remoted_tcp_sessions": r.get("remoted", {}).get("tcp_sessions"),
                "remoted_messages_received": r.get("remoted", {}).get("recv_bytes"),
            }
            for r in results
        ]

    def _search_incidents(self, query: str, limit: int) -> List[Dict]:
        """Search PostgreSQL incidents by keyword."""
        try:
            with get_db() as db:
                q = db.query(Incident).order_by(Incident.created_at.desc())
                # Simple keyword filter on analysis and rule_description
                for word in query.split()[:3]:
                    if len(word) > 3:
                        q = q.filter(
                            Incident.rule_description.ilike(f"%{word}%")
                            | Incident.analysis.ilike(f"%{word}%")
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
                        "analysis": (r.analysis or "")[:500],
                        "confidence_score": r.confidence_score,
                        "playbook_executed": r.playbook_executed,
                        "created_at": str(r.created_at),
                    }
                    for r in rows
                ]
        except Exception as e:
            logger.warning("rag.incident_search_failed: %s", e)
            return []

    def _search_correlated(self, query: str, limit: int) -> List[Dict]:
        """Search correlated incidents."""
        try:
            with get_db() as db:
                rows = (
                    db.query(CorrelatedIncident)
                    .order_by(CorrelatedIncident.created_at.desc())
                    .limit(limit)
                    .all()
                )
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

    def _search_suricata(self, query: str, limit: int) -> List[Dict]:
        """Read recent Suricata alerts."""
        try:
            events = self._suricata.read_recent_from_file(last_n_lines=5000)
            results = [e.to_dict() for e in events[:limit]]
            if not results:
                # Fallback: read raw JSON lines
                import json
                eve_path = "/var/log/suricata/eve.json"
                with open(eve_path, "r") as fh:
                    lines = fh.readlines()
                for line in reversed(lines[-5000:]):
                    try:
                        evt = json.loads(line.strip())
                        if evt.get("event_type") == "alert":
                            results.append(evt)
                            if len(results) >= limit:
                                break
                    except Exception:
                        continue
            return results
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
        """Get alert/incident statistics from OpenSearch + PostgreSQL."""
        stats = {"wazuh_alerts": {}, "db_incidents": {}}
        try:
            # OpenSearch alert stats — real Wazuh severity breakdown
            body = {
                "size": 0,
                "aggs": {
                    "by_level": {"terms": {"field": "rule.level", "size": 20}},
                    "by_agent": {"terms": {"field": "agent.name", "size": 20}},
                    "total": {"value_count": {"field": "_id"}},
                }
            }
            data = self._wazuh._indexer_request(
                "POST", "/wazuh-alerts-4.x-*/_search",
                json=body,
                headers={"Content-Type": "application/json"},
            )
            total = data.get("hits", {}).get("total", {}).get("value", 0)
            by_level = {str(b["key"]): b["doc_count"] for b in data.get("aggregations", {}).get("by_level", {}).get("buckets", [])}
            by_agent = {b["key"]: b["doc_count"] for b in data.get("aggregations", {}).get("by_agent", {}).get("buckets", [])}

            # Map Wazuh levels to severity
            critical = sum(v for k, v in by_level.items() if int(k) >= 13)
            high = sum(v for k, v in by_level.items() if 10 <= int(k) <= 12)
            medium = sum(v for k, v in by_level.items() if 7 <= int(k) <= 9)
            low = sum(v for k, v in by_level.items() if int(k) < 7)

            stats["wazuh_alerts"] = {
                "total": total,
                "by_severity": {"critical": critical, "high": high, "medium": medium, "low": low},
                "by_level": by_level,
                "by_agent": by_agent,
            }

            # Archive stats
            arch_data = self._wazuh._indexer_request(
                "POST", "/wazuh-archives-4.x-*/_search",
                json={"size": 0, "aggs": {"by_location": {"terms": {"field": "location", "size": 10}}}},
                headers={"Content-Type": "application/json"},
            )
            arch_total = arch_data.get("hits", {}).get("total", {}).get("value", 0)
            by_location = {b["key"]: b["doc_count"] for b in arch_data.get("aggregations", {}).get("by_location", {}).get("buckets", [])}
            stats["archives"] = {"total": arch_total, "by_location": by_location}

        except Exception as e:
            logger.warning("rag.stats_opensearch_failed: %s", e)

        # PostgreSQL incidents
        try:
            with get_db() as db:
                total = db.query(Incident).count()
                by_sev = {}
                for s in ["low", "medium", "high", "critical"]:
                    by_sev[s] = db.query(Incident).filter(Incident.severity == s).count()
                stats["db_incidents"] = {"total": total, "by_severity": by_sev}
        except Exception:
            pass

        return stats
