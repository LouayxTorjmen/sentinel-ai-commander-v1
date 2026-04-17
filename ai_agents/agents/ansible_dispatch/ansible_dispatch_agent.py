"""
Hybrid Ansible Dispatcher — static rule map + LLM fallback + safety gates.

Routing priority:
  1. Static map (rule_id → playbook) — fast, deterministic
  2. Group-based heuristics (e.g., "suricata" + "scan" → lateral_movement)
  3. LLM fallback — for novel alerts

Safety gates:
  - dry_run for rule_level < 7
  - manual approval for rule_level 7-9 (logs intent, doesn't execute)
  - auto-execute for rule_level >= 10 AND confidence >= threshold
"""
import json
import os
import dspy
import structlog
from ai_agents.agents.base_agent import BaseAgent
from ai_agents.dspy_modules.signatures import ResponseDecision
from ai_agents.tools.ansible_trigger import AnsibleTrigger
from ai_agents.config import get_settings
from ai_agents.llm.fallback import get_lm

logger = structlog.get_logger()

# ── Static rule → playbook map ─────────────────────────────────────────
# Wazuh rule IDs: https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html
STATIC_RULE_MAP = {
    # SSH brute force
    "5712": {"playbook": "brute_force_response", "severity": "high"},
    "5710": {"playbook": "brute_force_response", "severity": "high"},
    "5720": {"playbook": "brute_force_response", "severity": "high"},
    "100006": {"playbook": "brute_force_response", "severity": "high"},

    # Web attacks
    "31103": {"playbook": "incident_response", "severity": "high"},        # SQL injection
    "31104": {"playbook": "incident_response", "severity": "high"},        # XSS
    "31108": {"playbook": "incident_response", "severity": "high"},        # Command injection
    "31516": {"playbook": "incident_response", "severity": "medium"},      # Directory traversal

    # FIM events
    "550": {"playbook": "fim_restore_response", "severity": "medium"},     # File modified
    "554": {"playbook": "file_quarantine_response", "severity": "high"},   # File added (suspicious)
    "594": {"playbook": "fim_restore_response", "severity": "medium"},     # Registry modified

    # Rootkit detection
    "510": {"playbook": "malware_containment", "severity": "critical"},
    "511": {"playbook": "malware_containment", "severity": "critical"},

    # Privilege escalation / account compromise
    "40111": {"playbook": "compromised_user_response", "severity": "critical"},
    "5402": {"playbook": "compromised_user_response", "severity": "high"},  # sudo -s
    "5403": {"playbook": "compromised_user_response", "severity": "high"},  # su to root

    # Permissions tampering
    "5901": {"playbook": "permissions_restore_response", "severity": "medium"},

    # Port scans / recon
    "40503": {"playbook": "lateral_movement_response", "severity": "medium"},
    "86601": {"playbook": "lateral_movement_response", "severity": "medium"},  # Suricata nmap UA
}

# ── Group-based heuristics ────────────────────────────────────────────
# If rule_id isn't in static map, inspect rule.groups for keywords
GROUP_HEURISTICS = [
    (["suricata", "scan"], "lateral_movement_response", "medium"),
    (["suricata", "attack"], "incident_response", "high"),
    (["suricata", "trojan"], "malware_containment", "critical"),
    (["authentication_failed"], "brute_force_response", "high"),
    (["web_attack"], "incident_response", "high"),
    (["rootcheck"], "malware_containment", "critical"),
    (["rootkit"], "malware_containment", "critical"),
    (["syscheck"], "fim_restore_response", "medium"),
]


def route_alert(alert: dict) -> dict:
    """
    Decide which playbook to run based on alert metadata.
    Returns: {source, playbook, severity, confidence} or None.
    """
    rule = alert.get("rule", {})
    rule_id = str(rule.get("id", ""))
    rule_level = rule.get("level", 0)
    rule_groups = rule.get("groups", [])

    # 1. Static rule map
    if rule_id in STATIC_RULE_MAP:
        entry = STATIC_RULE_MAP[rule_id]
        return {
            "source": "static_map",
            "playbook": entry["playbook"],
            "severity": entry["severity"],
            "confidence": 0.95,
            "rule_id": rule_id,
        }

    # 2. Group heuristics
    groups_set = set(g.lower() for g in rule_groups)
    for required_groups, playbook, severity in GROUP_HEURISTICS:
        if all(rg in groups_set for rg in required_groups):
            return {
                "source": "group_heuristic",
                "playbook": playbook,
                "severity": severity,
                "confidence": 0.75,
                "rule_id": rule_id,
                "matched_groups": required_groups,
            }

    # 3. No match — caller should fall back to LLM
    return None


def extract_vars_from_alert(alert: dict) -> dict:
    """Extract common playbook vars from alert data."""
    data = alert.get("data", {})
    syscheck = alert.get("syscheck", {})
    return {
        "source_ip": data.get("srcip") or data.get("src_ip", ""),
        "dest_ip": data.get("dstip") or data.get("dest_ip", ""),
        "username": data.get("srcuser") or data.get("username", ""),
        "file_path": syscheck.get("path", ""),
        "target_hosts": alert.get("agent", {}).get("name", "all"),
    }


class HybridAnsibleDispatcher(BaseAgent):
    """Hybrid dispatcher — static routing first, LLM fallback."""
    name = "ansible_dispatch"

    def __init__(self):
        super().__init__()
        s = get_settings()
        self._decide = dspy.ChainOfThought(ResponseDecision)
        self._trigger = AnsibleTrigger()
        self._threshold = s.ansible_confidence_threshold

        # Safety thresholds
        self._auto_execute_level = int(os.getenv("ANSIBLE_AUTO_EXECUTE_LEVEL", "10"))
        self._dry_run_below_level = int(os.getenv("ANSIBLE_DRY_RUN_BELOW_LEVEL", "7"))

    async def run(self, input_data: dict) -> dict:
        alert = input_data.get("alert", {})
        analysis = input_data.get("analysis", "")
        incident_id = input_data.get("incident_id", "unknown")

        rule_level = alert.get("rule", {}).get("level", 0)
        rule_id = str(alert.get("rule", {}).get("id", ""))

        # Step 1: Try static routing
        decision = route_alert(alert)
        decision_source = decision["source"] if decision else None

        # Step 2: LLM fallback
        if not decision:
            self.logger.info("dispatch.llm_fallback", rule_id=rule_id)
            try:
                lm = get_lm()
                with dspy.context(lm=lm):
                    llm_decision = self._decide(
                        threat_analysis=analysis,
                        alert_type=input_data.get("alert_type", "other"),
                        severity=input_data.get("severity", "medium"),
                        confidence=str(input_data.get("confidence", 0.5)),
                    )
                if llm_decision.should_respond.strip().lower() == "yes":
                    decision = {
                        "source": "llm",
                        "playbook": llm_decision.playbook,
                        "severity": input_data.get("severity", "medium"),
                        "confidence": float(input_data.get("confidence", 0.5)),
                        "rule_id": rule_id,
                        "reasoning": llm_decision.reasoning,
                    }
                    decision_source = "llm"
                else:
                    return {"executed": False, "reason": f"LLM declined: {llm_decision.reasoning}", "playbook": None}
            except Exception as e:
                self.logger.warning("dispatch.llm_failed", error=str(e))
                return {"executed": False, "reason": f"LLM dispatch failed: {e}", "playbook": None}

        # Step 3: Safety gates
        dry_run = False
        if rule_level < self._dry_run_below_level:
            self.logger.info("dispatch.skip_low_severity", rule_level=rule_level)
            return {"executed": False, "reason": f"Rule level {rule_level} below response threshold", "playbook": decision["playbook"]}

        if rule_level < self._auto_execute_level:
            # Medium severity — dry run only
            dry_run = True
            self.logger.info("dispatch.dry_run", rule_level=rule_level, playbook=decision["playbook"])

        if decision.get("confidence", 0) < self._threshold:
            return {"executed": False, "reason": f"Confidence {decision.get('confidence')} below threshold {self._threshold}", "playbook": decision["playbook"]}

        # Step 4: Build playbook vars
        extra_vars = extract_vars_from_alert(alert)
        extra_vars.update({
            "incident_id": incident_id,
            "severity": decision["severity"],
            "dry_run": dry_run,
        })

        # Step 5: Execute
        try:
            result = await self._trigger.run_playbook(
                playbook=decision["playbook"],
                extra_vars=extra_vars,
            )
            return {
                "executed": True,
                "dry_run": dry_run,
                "playbook": decision["playbook"],
                "decision_source": decision_source,
                "extra_vars": extra_vars,
                "rule_id": rule_id,
                "rule_level": rule_level,
                "result": result,
            }
        except Exception as e:
            self.logger.error("dispatch.execution_failed", error=str(e))
            return {"executed": False, "reason": f"Execution failed: {e}", "playbook": decision["playbook"]}


# Alias to keep the existing import path working
AnsibleDispatchAgent = HybridAnsibleDispatcher
