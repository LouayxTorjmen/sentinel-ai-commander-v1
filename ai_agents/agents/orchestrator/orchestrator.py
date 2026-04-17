import uuid
import structlog
from datetime import datetime
from ai_agents.agents.log_analyzer.log_analyzer import LogAnalyzerAgent
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
        self.log_analyzer = LogAnalyzerAgent()
        self.threat_intel = ThreatIntelAgent()
        self.cve_scanner = CVEScannerAgent()
        self.incident_responder = IncidentResponderAgent()
        self.ansible_dispatch = AnsibleDispatchAgent()

    async def process_alert(self, alert: dict) -> dict:
        incident_id = str(uuid.uuid4())
        logger.info("orchestrator.processing", incident_id=incident_id, rule_id=alert.get("rule", {}).get("id"))

        # Step 1 — Log Analysis + Classification
        log_result = await self.log_analyzer.execute({"alert": alert, "incident_id": incident_id})

        # Step 2 — Threat Intel
        intel_result = await self.threat_intel.execute({
            "mitre_techniques": log_result.get("mitre_techniques", []),
            "iocs": log_result.get("iocs", {}),
            "incident_id": incident_id,
        })

        # Step 3 — CVE Scan (keywords from summary)
        summary = log_result.get("summary", "")
        keywords = [w for w in summary.split()[:5] if len(w) > 4]
        cve_result = await self.cve_scanner.execute({"keywords": keywords, "incident_id": incident_id})

        # Step 4 — Incident Response Analysis
        ir_result = await self.incident_responder.execute({
            "summary": summary,
            "threat_intel": intel_result,
            "incident_id": incident_id,
        })

        # Step 5 — Ansible Dispatch Decision
        dispatch_result = await self.ansible_dispatch.execute({
            "alert": alert,
            "analysis": ir_result.get("analysis", ""),
            "alert_type": log_result.get("alert_type", "other"),
            "severity": log_result.get("severity", "medium"),
            "confidence": log_result.get("confidence", 0.0),
            "source_ip": alert.get("data", {}).get("srcip", ""),
            "incident_id": incident_id,
        })

        # Persist incident to DB
        severity_str = log_result.get("severity", "medium").lower()
        try:
            with get_db() as db:
                incident = Incident(
                    id=incident_id,
                    wazuh_alert_id=str(alert.get("id", "")),
                    rule_id=alert.get("rule", {}).get("id"),
                    rule_description=alert.get("rule", {}).get("description"),
                    severity=SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM),
                    status=IncidentStatus.RESPONDING if dispatch_result.get("executed") else IncidentStatus.ANALYZING,
                    source_ip=alert.get("data", {}).get("srcip"),
                    dest_ip=alert.get("data", {}).get("dstip"),
                    mitre_techniques=log_result.get("mitre_techniques", []),
                    alert_data=alert,
                    analysis=ir_result.get("analysis"),
                    recommended_action=dispatch_result.get("playbook"),
                    confidence_score=log_result.get("confidence", 0.0),
                    playbook_executed=dispatch_result.get("playbook") if dispatch_result.get("executed") else None,
                    playbook_result=dispatch_result.get("result"),
                )
                db.add(incident)
        except Exception as e:
            logger.error("orchestrator.db.failed", incident_id=incident_id, error=str(e))

        # Cache in Redis for fast API retrieval
        get_redis().set(f"incident:{incident_id}", {
            "incident_id": incident_id,
            "alert_type": log_result.get("alert_type"),
            "severity": log_result.get("severity"),
            "summary": summary,
            "analysis": ir_result.get("analysis"),
            "mitre_techniques": log_result.get("mitre_techniques"),
            "dispatch": dispatch_result,
            "risk_score": ir_result.get("risk_score"),
        })

        return {
            "incident_id": incident_id,
            "alert_type": log_result.get("alert_type"),
            "severity": log_result.get("severity"),
            "mitre_techniques": log_result.get("mitre_techniques"),
            "summary": summary,
            "analysis": ir_result.get("analysis"),
            "risk_score": ir_result.get("risk_score"),
            "dispatch": dispatch_result,
            "cves_found": cve_result.get("total", 0),
        }
