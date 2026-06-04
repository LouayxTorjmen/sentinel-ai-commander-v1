import uuid
import structlog
from datetime import datetime
from ai_agents.agents.log_analyzer.log_analyzer import LogAnalyzerAgent
from ai_agents.agents.ansible_dispatch.ansible_dispatch_agent import STATIC_RULE_MAP
from ai_agents.agents.threat_intel.threat_intel_agent import ThreatIntelAgent
from ai_agents.agents.vuln_scanner.cve_scanner import CVEScannerAgent
from ai_agents.agents.incident_response.incident_responder import IncidentResponderAgent
from ai_agents.agents.ansible_dispatch.ansible_dispatch_agent import AnsibleDispatchAgent
from ai_agents.database.db_manager import get_db
from ai_agents.database.models import Incident, SeverityLevel, IncidentStatus
from ai_agents.integrations.redis_manager import get_redis

logger = structlog.get_logger()

SEVERITY_MAP = {
    "low": SeverityLevel.LOW,
    "medium": SeverityLevel.MEDIUM,
    "high": SeverityLevel.HIGH,
    "critical": SeverityLevel.CRITICAL,
}

class OrchestratorAgent:
    def __init__(self):
        self.log_analyzer = LogAnalyzerAgent()     # kept for Phase 3 unknown-rule triage
        self.ansible_dispatch = AnsibleDispatchAgent()
        # Retired: ThreatIntelAgent (no-op), CVEScannerAgent (replaced by tool),
        # IncidentResponderAgent (redundant with chatbot reasoning)

    async def process_alert(self, alert: dict) -> dict:
        incident_id = str(uuid.uuid4())
        logger.info("orchestrator.processing", incident_id=incident_id, rule_id=alert.get("rule", {}).get("id"))
        # Fast-path: skip ALL LLM agents for rules in STATIC_RULE_MAP
        rule_id_str = str(alert.get("rule", {}).get("id", ""))
        if rule_id_str in STATIC_RULE_MAP:
            dispatch_result = await self.ansible_dispatch.execute({"alert": alert, "analysis": "static_map_fast_path", "alert_type": "known_threat", "severity": STATIC_RULE_MAP[rule_id_str].get("severity", "high"), "confidence": 0.95, "source_ip": ((alert.get("data") or {}).get("srcip") or (alert.get("data") or {}).get("src_ip") or (((alert.get("data") or {}).get("win") or {}).get("eventdata") or {}).get("ipAddress") or ""), "incident_id": incident_id})
            return {"incident_id": incident_id, "dispatch": dispatch_result, "fast_path": True}


        # Phase 3 placeholder — LLM pipeline disabled, static-only mode
        # Non-static-map alerts are instantly declined by the dispatcher
        dispatch_result = await self.ansible_dispatch.execute({
            "alert": alert,
            "analysis": "static_only_mode",
            "alert_type": "other",
            "severity": "low",
            "confidence": 0.0,
            "source_ip": ((alert.get("data") or {}).get("srcip") or (alert.get("data") or {}).get("src_ip") or (((alert.get("data") or {}).get("win") or {}).get("eventdata") or {}).get("ipAddress") or ""),
            "incident_id": incident_id,
        })

        # Persist incident to DB
        try:
            with get_db() as db:
                incident = Incident(
                    id=incident_id,
                    wazuh_alert_id=str(alert.get("id", "")),
                    rule_id=alert.get("rule", {}).get("id"),
                    rule_description=alert.get("rule", {}).get("description"),
                    severity=SeverityLevel.MEDIUM,
                    status=IncidentStatus.RESPONDING if (dispatch_result or {}).get("executed") else IncidentStatus.ANALYZING,
                    source_ip=alert.get("data", {}).get("srcip"),
                    dest_ip=alert.get("data", {}).get("dstip"),
                    mitre_techniques=[],
                    alert_data=alert,
                    analysis="static_only_mode",
                    recommended_action=(dispatch_result or {}).get("playbook"),
                    confidence_score=0.0,
                    playbook_executed=(dispatch_result or {}).get("playbook") if (dispatch_result or {}).get("executed") else None,
                    playbook_result=(dispatch_result or {}).get("result"),
                )
                db.add(incident)
        except Exception as e:
            logger.error("orchestrator.db.failed", incident_id=incident_id, error=str(e))

        # Cache minimal incident record (Phase 3: LLM analysis not yet wired)
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
        }
