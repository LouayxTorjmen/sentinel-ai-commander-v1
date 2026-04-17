import json
import dspy
import structlog
from ai_agents.agents.base_agent import BaseAgent
from ai_agents.dspy_modules.signatures import AlertClassification, IOCExtraction
from ai_agents.config import get_settings

logger = structlog.get_logger()

def _build_lm():
    s = get_settings()
    return dspy.LM(
        model=f"groq/{s.llm_model}",
        api_key=s.groq_api_key,
        temperature=s.llm_temperature,
        max_tokens=s.llm_max_tokens,
    )

class LogAnalyzerAgent(BaseAgent):
    name = "log_analyzer"

    def __init__(self):
        super().__init__()
        lm = _build_lm()
        dspy.configure(lm=lm)
        self._classify = dspy.ChainOfThought(AlertClassification)
        self._extract_iocs = dspy.ChainOfThought(IOCExtraction)

    async def run(self, input_data: dict) -> dict:
        alert = input_data.get("alert", {})
        alert_json = json.dumps(alert, default=str)

        self.logger.info("log_analyzer.classifying", rule_id=alert.get("rule", {}).get("id"))

        classification = self._classify(alert_json=alert_json)
        iocs = self._extract_iocs(alert_json=alert_json)

        mitre_list = [t.strip() for t in classification.mitre_techniques.split(",") if t.strip()]

        return {
            "alert_type": classification.alert_type,
            "severity": classification.severity,
            "mitre_techniques": mitre_list,
            "confidence": float(classification.confidence),
            "summary": classification.summary,
            "iocs": {
                "ip_addresses": [i.strip() for i in iocs.ip_addresses.split(",") if i.strip()],
                "domains": [d.strip() for d in iocs.domains.split(",") if d.strip()],
                "hashes": [h.strip() for h in iocs.hashes.split(",") if h.strip()],
                "usernames": [u.strip() for u in iocs.usernames.split(",") if u.strip()],
            },
        }
