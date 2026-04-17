import dspy
import structlog
from ai_agents.agents.base_agent import BaseAgent
from ai_agents.dspy_modules.signatures import ThreatAnalysis
from ai_agents.config import get_settings

logger = structlog.get_logger()

class IncidentResponderAgent(BaseAgent):
    name = "incident_response"

    def __init__(self):
        super().__init__()
        s = get_settings()
        lm = dspy.LM(
            model=f"groq/{s.llm_model}",
            api_key=s.groq_api_key,
            temperature=s.llm_temperature,
            max_tokens=s.llm_max_tokens,
        )
        dspy.configure(lm=lm)
        self._analyze = dspy.ChainOfThought(ThreatAnalysis)

    async def run(self, input_data: dict) -> dict:
        alert_summary = input_data.get("summary", "")
        threat_intel = str(input_data.get("threat_intel", {}))

        analysis = self._analyze(
            alert_summary=alert_summary,
            threat_intel=threat_intel,
        )

        return {
            "analysis": analysis.analysis,
            "attack_chain": analysis.attack_chain,
            "risk_score": float(analysis.risk_score) if analysis.risk_score.replace(".", "").isdigit() else 50.0,
        }
