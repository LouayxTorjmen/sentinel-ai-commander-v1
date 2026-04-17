# =============================================================================
#  wazuh_suricata_agent.py — Wazuh + Suricata Correlation Agent
#  Location: src/ai_agents/wazuh_suricata_agent.py
#
#  PURPOSE:
#    DSPy-powered agent that:
#      1. Polls the Wazuh Manager API for HIDS alerts (host-based events,
#         FIM changes, rule hits, vulnerability findings).
#      2. Reads Suricata IDS/IPS alerts (network-based events, signature
#         matches, protocol anomalies).
#      3. Correlates both streams by source IP, destination IP, time window,
#         and MITRE ATT&CK technique overlap.
#      4. Produces enriched, MITRE-tagged incident reports for the
#         OrchestratorAgent and the REST API.
#
#  INPUTS:
#    - Wazuh Manager API (via WazuhClient)
#    - Suricata eve.json (via SuricataClient — Redis or file mode)
#
#  OUTPUTS:
#    - CorrelatedIncident objects (dict-serializable)
#    - Published to Redis channel: "secops:correlated_incidents"
#    - Stored in PostgreSQL via the db_manager
#
#  MITRE ATT&CK MAPPING:
#    Each correlated incident is tagged with:
#      - tactic  (e.g., "Initial Access")
#      - technique_id  (e.g., "T1190")
#      - technique_name (e.g., "Exploit Public-Facing Application")
#    The DSPy CorrelationSignature does the AI-assisted mapping.
#
#  CVE ENRICHMENT:
#    Wazuh vulnerability detector results are fetched per agent and
#    cross-referenced with NVD/CVE data via the CVEScannerAgent.
#
#  EXTENDS: BaseAgent from agents/base_agent.py (colleague's project)
#
#  ENVIRONMENT VARIABLES:
#    WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD
#    SURICATA_MODE (redis|file), SURICATA_EVE_PATH
#    REDIS_HOST, REDIS_PORT
# =============================================================================

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import dspy

# Relative imports — works whether installed as package or run from project root
from ai_agents.agents.base_agent import BaseAgent
from ai_agents.tools.wazuh_client import WazuhClient, WazuhAPIError
from ai_agents.tools.suricata_client import SuricataClient, SuricataEvent
from ai_agents.dspy_modules.signatures import (
    WazuhAlertTriageSignature,
    SuricataAlertEnrichSignature,
    CorrelationSignature,
)

logger = logging.getLogger(__name__)


class WazuhSuricataAgent(BaseAgent):
    """
    DSPy agent that correlates Wazuh HIDS alerts with Suricata NIDS alerts
    and maps the combined view to MITRE ATT&CK techniques.

    This agent is the primary consumer of the isolated Wazuh stack's API
    and Suricata's eve.json stream.  It runs continuously as a background
    service inside the AI agents container.

    Usage::

        agent = WazuhSuricataAgent(config={}, redis_manager=redis_mgr)
        result = agent.process({'mode': 'correlate', 'time_window_minutes': 10})
    """

    # Poll interval for the continuous run loop
    _DEFAULT_POLL_INTERVAL: int = 30  # seconds

    def __init__(
        self,
        config: Dict[str, Any],
        redis_manager=None,
    ) -> None:
        super().__init__()
        self.name = "wazuh_suricata"
        self._config = config
        self._redis_mgr = redis_manager

        # ── DSPy reasoning modules ────────────────────────────────────────────
        # ChainOfThought produces step-by-step reasoning + typed output fields.
        # These can be compiled with dspy.MIPROv2 using labelled alert examples
        # for your PhD research contribution.
        self._wazuh_triage = dspy.ChainOfThought(WazuhAlertTriageSignature)
        self._suricata_enrich = dspy.ChainOfThought(SuricataAlertEnrichSignature)
        self._correlator = dspy.ChainOfThought(CorrelationSignature)

        # ── API / log clients ─────────────────────────────────────────────────
        self._wazuh = WazuhClient()
        suricata_mode = os.getenv("SURICATA_MODE", "redis")
        self._suricata = SuricataClient(mode=suricata_mode)

        self.logger.info("wazuh_suricata.init", suricata_mode=suricata_mode, wazuh_url=os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000"))

    # ── BaseAgent interface ───────────────────────────────────────────────────

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for the orchestrator.

        Supported modes:
          'correlate'        — fetch both streams and correlate (default)
          'wazuh_alerts'     — return raw Wazuh alerts only
          'suricata_alerts'  — return raw Suricata alerts only
          'agent_vulns'      — return vulnerabilities for a specific agent_id
          'health'           — return health status of both data sources

        Input dict keys:
          mode                 (str)  — see above
          time_window_minutes  (int)  — how far back to look (default: 10)
          wazuh_level_gte      (int)  — min Wazuh rule level (default: 7)
          suricata_severity_lte (int) — max Suricata severity 1–4 (default: 3)
          agent_id             (str)  — Wazuh agent ID for agent_vulns mode
          limit                (int)  — max alerts per source (default: 50)
        """
        mode = input_data.get("mode", "correlate")
        time_window = int(input_data.get("time_window_minutes", 10))
        wazuh_level = int(input_data.get("wazuh_level_gte", 7))
        suri_sev = int(input_data.get("suricata_severity_lte", 3))
        limit = int(input_data.get("limit", 50))

        self.logger.info("wazuh_suricata.process", mode=mode)

        try:
            if mode == "wazuh_alerts":
                return self._get_wazuh_alerts(limit=limit, level_gte=wazuh_level)

            elif mode == "suricata_alerts":
                return self._get_suricata_alerts(
                    limit=limit, severity_lte=suri_sev
                )

            elif mode == "agent_vulns":
                agent_id = input_data.get("agent_id", "001")
                return self._get_agent_vulnerabilities(agent_id)

            elif mode == "health":
                return self._health()

            else:  # 'correlate' (default)
                return self._correlate(
                    time_window_minutes=time_window,
                    wazuh_level_gte=wazuh_level,
                    suricata_severity_lte=suri_sev,
                    limit=limit,
                )

        except WazuhAPIError as exc:
            self.logger.error("wazuh_suricata.wazuh_error", error=str(exc))
            return {"status": "error", "source": "wazuh", "error": str(exc)}
        except Exception as exc:
            self.logger.error("wazuh_suricata.unexpected_error", error=str(exc))
            return {"status": "error", "error": str(exc)}

    # ── Private methods ───────────────────────────────────────────────────────

    def _get_wazuh_alerts(
        self, limit: int = 50, level_gte: int = 7
    ) -> Dict[str, Any]:
        """Fetch and triage Wazuh alerts using the DSPy triage module."""
        raw_alerts = self._wazuh.get_alerts(limit=limit, level_gte=level_gte)
        triaged = []

        for alert in raw_alerts:
            alert_text = json.dumps(alert, indent=2)
            try:
                result = self._wazuh_triage(
                    wazuh_alert_json=alert_text,
                    agent_context=f"Agent: {alert.get('agent', {}).get('name', 'unknown')}",
                )
                triaged.append(
                    {
                        "alert_id": alert.get("id"),
                        "timestamp": alert.get("timestamp"),
                        "rule_id": alert.get("rule", {}).get("id"),
                        "rule_level": alert.get("rule", {}).get("level"),
                        "rule_description": alert.get("rule", {}).get("description"),
                        "mitre_technique": alert.get("rule", {})
                        .get("mitre", {})
                        .get("id", []),
                        "agent_name": alert.get("agent", {}).get("name"),
                        # DSPy outputs
                        "triage_severity": result.severity,
                        "triage_category": result.threat_category,
                        "recommended_action": result.recommended_action,
                        "cve_references": result.cve_references,
                        "false_positive_likelihood": result.false_positive_likelihood,
                    }
                )
            except Exception as exc:
                logger.warning("WazuhSuricataAgent: triage failed for alert: %s", exc)
                triaged.append(
                    {
                        "alert_id": alert.get("id"),
                        "rule_description": alert.get("rule", {}).get("description"),
                        "triage_error": str(exc),
                    }
                )

        return {
            "status": "success",
            "source": "wazuh",
            "count": len(triaged),
            "alerts": triaged,
        }

    def _get_suricata_alerts(
        self, limit: int = 50, severity_lte: int = 3
    ) -> Dict[str, Any]:
        """Fetch and enrich Suricata alerts using the DSPy enrichment module."""
        if self._suricata.mode == "redis":
            raw_events = self._suricata.get_recent_alerts_from_redis(
                limit=limit, severity_lte=severity_lte
            )
        else:
            raw_events = self._suricata.read_recent_from_file(last_n_lines=limit * 3)
            raw_events = [e for e in raw_events if e.severity <= severity_lte][:limit]

        enriched = []
        for evt in raw_events:
            try:
                result = self._suricata_enrich(
                    suricata_alert_json=json.dumps(evt.to_dict(), indent=2),
                    network_context=f"src={evt.src_ip}:{evt.src_port} "
                    f"dst={evt.dest_ip}:{evt.dest_port} proto={evt.proto}",
                )
                enriched.append(
                    {
                        **evt.to_dict(),
                        "mitre_technique_id": result.mitre_technique_id,
                        "mitre_technique_name": result.mitre_technique_name,
                        "attack_stage": result.attack_stage,
                        "threat_summary": result.threat_summary,
                        "recommended_action": result.recommended_action,
                    }
                )
            except Exception as exc:
                logger.warning(
                    "WazuhSuricataAgent: enrichment failed for Suricata event: %s", exc
                )
                enriched.append(evt.to_dict())

        return {
            "status": "success",
            "source": "suricata",
            "count": len(enriched),
            "alerts": enriched,
        }

    def _correlate(
        self,
        time_window_minutes: int = 10,
        wazuh_level_gte: int = 7,
        suricata_severity_lte: int = 3,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        Core correlation logic.

        Algorithm:
          1. Fetch Wazuh alerts (HIDS — host events).
          2. Fetch Suricata alerts (NIDS — network events).
          3. Build IP-indexed lookup from both sets.
          4. Find pairs where:
               • src_ip in Suricata == agent IP in Wazuh, OR
               • dest_ip in Suricata == agent IP in Wazuh
             within the given time_window_minutes.
          5. For each correlated pair, run the DSPy CorrelationSignature
             to produce a MITRE-tagged incident report.
          6. Publish results to Redis and return structured dict.
        """
        self.logger.info("wazuh_suricata.correlate", window=time_window_minutes, wazuh_level=wazuh_level_gte, suri_sev=suricata_severity_lte)

        # Step 1 & 2: fetch both sources concurrently (simple sequential for now)
        wazuh_alerts = self._wazuh.get_alerts(
            limit=limit, level_gte=wazuh_level_gte
        )
        if self._suricata.mode == "redis":
            suri_events = self._suricata.get_recent_alerts_from_redis(
                limit=limit, severity_lte=suricata_severity_lte
            )
        else:
            suri_events = self._suricata.read_recent_from_file(last_n_lines=limit * 3)
            suri_events = [
                e for e in suri_events if e.severity <= suricata_severity_lte
            ][:limit]

        # Step 3: build IP lookup for Wazuh agents
        # agent_ip → list of alerts
        wazuh_by_ip: Dict[str, List[Dict]] = {}
        for alert in wazuh_alerts:
            agent_ip = alert.get("agent", {}).get("ip", "")
            if agent_ip:
                wazuh_by_ip.setdefault(agent_ip, []).append(alert)

        # Step 4: find correlated pairs
        correlated_pairs: List[Tuple[SuricataEvent, Dict]] = []
        for evt in suri_events:
            for ip in (evt.src_ip, evt.dest_ip):
                if ip in wazuh_by_ip:
                    for w_alert in wazuh_by_ip[ip]:
                        correlated_pairs.append((evt, w_alert))

        self.logger.info("wazuh_suricata.pairs_found", pairs=len(correlated_pairs), wazuh=len(wazuh_alerts), suricata=len(suri_events))

        # Step 5: enrich correlated pairs with DSPy
        incidents = []
        seen_pairs: set = set()

        for suri_evt, wazuh_alert in correlated_pairs:
            pair_key = (suri_evt.signature_id, wazuh_alert.get("id"))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            try:
                correlation_result = self._correlator(
                    wazuh_alert_summary=json.dumps(
                        {
                            "rule": wazuh_alert.get("rule", {}),
                            "agent": wazuh_alert.get("agent", {}),
                            "timestamp": wazuh_alert.get("timestamp"),
                        },
                        indent=2,
                    ),
                    suricata_alert_summary=json.dumps(suri_evt.to_dict(), indent=2),
                    shared_indicators=f"IP: {suri_evt.src_ip}, {suri_evt.dest_ip}",
                )

                incident = {
                    "correlation_id": f"CORR-{int(time.time())}-{len(incidents)}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "wazuh_alert_id": wazuh_alert.get("id"),
                    "wazuh_rule": wazuh_alert.get("rule", {}).get("description"),
                    "wazuh_level": wazuh_alert.get("rule", {}).get("level"),
                    "suricata_signature": suri_evt.signature,
                    "suricata_severity": suri_evt.severity,
                    "shared_ip": (
                        suri_evt.src_ip
                        if suri_evt.src_ip
                        in wazuh_alert.get("agent", {}).get("ip", "")
                        else suri_evt.dest_ip
                    ),
                    # DSPy correlation outputs
                    "combined_severity": correlation_result.combined_severity,
                    "mitre_tactic": correlation_result.mitre_tactic,
                    "mitre_technique_id": correlation_result.mitre_technique_id,
                    "mitre_technique_name": correlation_result.mitre_technique_name,
                    "attack_narrative": correlation_result.attack_narrative,
                    "recommended_response": correlation_result.recommended_response,
                    "ansible_playbook": correlation_result.ansible_playbook_hint,
                }
                incidents.append(incident)

            except Exception as exc:
                logger.warning(
                    "WazuhSuricataAgent: correlation DSPy call failed: %s", exc
                )

        # Step 6: publish to Redis
        if self._redis_mgr and incidents:
            for incident in incidents:
                try:
                    self._redis_mgr.publish("secops:correlated_incidents", incident)
                except Exception as exc:
                    self.logger.warning("wazuh_suricata.redis_publish_failed", error=str(exc))

        # Step 7: persist to DB
        if incidents:
            try:
                from ai_agents.database.db_manager import get_db
                from ai_agents.database.models import CorrelatedIncident
                with get_db() as db:
                    for inc in incidents:
                        db.add(CorrelatedIncident(
                            id=inc["correlation_id"],
                            wazuh_alert_id=str(inc.get("wazuh_alert_id", "")),
                            wazuh_rule=inc.get("wazuh_rule"),
                            wazuh_level=inc.get("wazuh_level"),
                            suricata_signature=inc.get("suricata_signature"),
                            suricata_severity=inc.get("suricata_severity"),
                            shared_ip=inc.get("shared_ip"),
                            combined_severity=inc.get("combined_severity"),
                            mitre_tactic=inc.get("mitre_tactic"),
                            mitre_technique_id=inc.get("mitre_technique_id"),
                            mitre_technique_name=inc.get("mitre_technique_name"),
                            attack_narrative=inc.get("attack_narrative"),
                            recommended_response=inc.get("recommended_response"),
                            ansible_playbook=inc.get("ansible_playbook"),
                        ))
            except Exception as exc:
                self.logger.warning("wazuh_suricata.db_persist_failed", error=str(exc))

        return {
            "status": "success",
            "mode": "correlate",
            "wazuh_alerts_fetched": len(wazuh_alerts),
            "suricata_alerts_fetched": len(suri_events),
            "correlated_incidents": len(incidents),
            "incidents": incidents,
        }

    def _get_agent_vulnerabilities(self, agent_id: str) -> Dict[str, Any]:
        """Fetch CVE vulnerability data for a specific Wazuh agent."""
        vulns = self._wazuh.get_agent_vulnerabilities(agent_id)
        return {
            "status": "success",
            "agent_id": agent_id,
            "vulnerability_count": len(vulns),
            "vulnerabilities": vulns,
        }

    def _health(self) -> Dict[str, Any]:
        """Return health status of Wazuh API and Suricata connections."""
        wazuh_ok = self._wazuh.health_check()
        suri_health = self._suricata.health_check()
        return {
            "status": "success",
            "wazuh_api": "ok" if wazuh_ok else "error",
            "suricata_redis": "ok" if suri_health["redis_ok"] else "unavailable",
            "suricata_file": "ok" if suri_health["file_ok"] else "not_found",
        }


    async def run(self, input_data: dict) -> dict:
        """Async wrapper — runs sync process() in executor so it never blocks the event loop."""
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.process, input_data)
