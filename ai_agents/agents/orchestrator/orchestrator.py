# =============================================================================
# REPLACEMENT for ai_agents/agents/orchestrator/orchestrator.py
# Changes from current version:
#   1. _phase3_dispatch() method added — LLM triage for unknown rules
#   2. FIM noise path exclusion in gather_alert_context call
#   3. Dead agent imports removed (already done)
#   4. Redis.set() bug fixed (already done)
# =============================================================================

import uuid
import json
import os
import logging
import structlog
import requests
from datetime import datetime
from ai_agents.agents.log_analyzer.log_analyzer import LogAnalyzerAgent
from ai_agents.agents.ansible_dispatch.ansible_dispatch_agent import (
    STATIC_RULE_MAP, AnsibleDispatchAgent
)
from ai_agents.agents.ansible_dispatch.ansible_dispatch_agent import extract_vars_from_alert
from ai_agents.database.db_manager import get_db
from ai_agents.database.models import Incident, SeverityLevel, IncidentStatus
from ai_agents.integrations.redis_manager import get_redis
from ai_agents.tools.ansible_trigger import AnsibleTrigger
from ai_agents.config import get_settings

logger = structlog.get_logger()

SEVERITY_MAP = {
    "low": SeverityLevel.LOW,
    "medium": SeverityLevel.MEDIUM,
    "high": SeverityLevel.HIGH,
    "critical": SeverityLevel.CRITICAL,
}

# ── Phase 3 config ─────────────────────────────────────────────────────────────
PHASE3_ENABLED   = os.getenv("PHASE3_ENABLED", "true").lower() == "true"
PHASE3_MIN_LEVEL = int(os.getenv("PHASE3_MIN_LEVEL", "7"))   # ignore low-level unknown rules
PHASE3_DRY_RUN   = os.getenv("PHASE3_DRY_RUN", "false").lower() == "true"

# Playbooks the LLM is allowed to choose (same allow-list as chatbot)
_PHASE3_ALLOWED_PLAYBOOKS = {
    "block_ip", "incident_response", "win_incident_response",
    "fim_restore_response", "win_fim_restore_response",
    "harden_nginx_tls", "mysql_credential_response",
    "block_adcs_abuse", "block_dns_exfil",
    "brute_force_response", "win_brute_force_response",
    "lateral_movement_response", "win_lateral_movement_response",
    "malware_containment", "win_malware_containment",
}

# Paths the context gatherer should exclude (our own Ansible temp files)
_FIM_NOISE_PATHS = {
    "/tmp/ansible_", "/root/.ansible/", "/home/louay/.ansible/",
    "/var/cache/apt/", "/var/lib/apt/", "/var/log/wtmp",
    "/var/log/btmp", "/var/log/lastlog",
    "/etc/cups/subscriptions",  # CUPS subscription churn
}


class OrchestratorAgent:
    def __init__(self):
        self.log_analyzer    = LogAnalyzerAgent()
        self.ansible_dispatch = AnsibleDispatchAgent()
        self._trigger        = AnsibleTrigger()
        self._settings       = get_settings()

    async def process_alert(self, alert: dict) -> dict:
        incident_id  = str(uuid.uuid4())
        rule_id_str  = str(alert.get("rule", {}).get("id", ""))
        rule_level   = alert.get("rule", {}).get("level", 0)
        agent_name   = (alert.get("agent") or {}).get("name", "")

        logger.info("orchestrator.processing",
                    incident_id=incident_id,
                    rule_id=rule_id_str,
                    agent=agent_name)

        # ── FAST PATH: known rule → static dispatch ───────────────────────────
        if rule_id_str in STATIC_RULE_MAP:
            dispatch_result = await self.ansible_dispatch.execute({
                "alert":      alert,
                "analysis":   "static_map_fast_path",
                "alert_type": "known_threat",
                "severity":   STATIC_RULE_MAP[rule_id_str].get("severity", "high"),
                "confidence": 0.95,
                "source_ip":  _extract_src_ip(alert),
                "incident_id": incident_id,
            })
            return {
                "incident_id": incident_id,
                "dispatch":    dispatch_result,
                "fast_path":   True,
                "phase":       "phase2_static",
            }

        # ── PHASE 3: unknown rule → LLM triage ───────────────────────────────
        if PHASE3_ENABLED and rule_level >= PHASE3_MIN_LEVEL:
            return await self._phase3_dispatch(alert, rule_id_str, agent_name, incident_id)

        # ── SKIP: unknown rule, below threshold or Phase 3 disabled ──────────
        logger.debug("orchestrator.skip",
                     rule_id=rule_id_str,
                     level=rule_level,
                     reason="no_static_rule_phase3_disabled_or_below_threshold")
        return {
            "incident_id": incident_id,
            "dispatch":    {"executed": False, "reason": "no_static_rule_match"},
            "fast_path":   False,
            "phase":       "skipped",
        }

    # ── Phase 3 LLM triage ───────────────────────────────────────────────────

    async def _phase3_dispatch(
        self,
        alert: dict,
        rule_id: str,
        agent_name: str,
        incident_id: str,
    ) -> dict:
        """
        Unknown rule triage:
          1. Gather deduplicated context via gather_alert_context
          2. Build a tight LLM prompt (single-shot, no tool loop)
          3. Parse JSON decision from LLM response
          4. Validate against allow-list + safety guards
          5. Execute or skip
        """
        logger.info("orchestrator.phase3.start",
                    incident_id=incident_id,
                    rule_id=rule_id,
                    agent=agent_name)

        # ── Step 1: Gather deduplicated context ───────────────────────────────
        try:
            from ai_agents.rag.agent_tools import gather_alert_context
            ctx = gather_alert_context(
                agent_name=agent_name or None,
                time_window="30m",
                min_level=0,
                max_raw_alerts=500,
                max_unique_types=80,
            )
            # Filter Ansible/system noise from unique_events before sending to LLM
            ctx["unique_events"] = [
                e for e in ctx.get("unique_events", [])
                if not any(
                    noise in (e.get("syscheck_path") or "")
                    for noise in _FIM_NOISE_PATHS
                )
            ]
        except Exception as exc:
            logger.warning("orchestrator.phase3.context_gather_failed", error=str(exc))
            ctx = {"summary": {}, "mitre_summary": [], "unique_events": []}

        # ── Step 2: Build prompt ──────────────────────────────────────────────
        rule_desc   = alert.get("rule", {}).get("description", "")
        rule_level  = alert.get("rule", {}).get("level", 0)
        rule_groups = alert.get("rule", {}).get("groups", [])
        src_ip      = _extract_src_ip(alert)

        allowed_str = "\n".join(f"  - {p}" for p in sorted(_PHASE3_ALLOWED_PLAYBOOKS))
        context_str = json.dumps({
            "summary":       ctx.get("summary", {}),
            "mitre_summary": ctx.get("mitre_summary", []),
            "recent_unique_events": ctx.get("unique_events", [])[:40],
        }, default=str)
        if len(context_str) > 6000:
            context_str = context_str[:6000] + "...(truncated)"

        prompt = f"""You are SENTINEL-AI, an automated SOC triage agent.

A Wazuh security alert has fired for a rule NOT in the static response map.
Your job: analyse the alert + recent context, then decide on a response.

TRIGGERING ALERT:
  Rule ID      : {rule_id}
  Description  : {rule_desc}
  Level        : {rule_level} / 15
  Groups       : {rule_groups}
  Agent        : {agent_name}
  Source IP    : {src_ip or '(none)'}

RECENT ACTIVITY CONTEXT (last 30 min, deduplicated):
{context_str}

LAB TOPOLOGY:
  - Ubuntu-agent-web (10.50.0.12): web server, runs nginx + DVWA
  - srv-sql (10.50.0.13): MySQL database server
  - srv-dns-bind (10.50.0.11): DNS server running dnsdist/BIND
  - srv-ad-dns (10.50.0.10): Windows domain controller
  - srv-ftp (10.50.0.14): Windows FTP server
  - sentinel-fw (10.60.0.1): pfSense gateway running Suricata
  - Attacker: Kali Linux at 10.70.0.0/24

ALLOWED PLAYBOOKS:
{allowed_str}

INSTRUCTIONS:
- If confidence < 0.6, use action "no_action"
- Never block loopback (127.0.0.1) or management subnet (10.60.0.0/24)
- For Windows agents (srv-ad-dns, srv-ftp) use win_* playbook variants
- For Linux agents use standard variants

Respond ONLY with this JSON (no other text):
{{
  "action": "<playbook_name_or_no_action>",
  "severity": "<low|medium|high|critical>",
  "confidence": <0.0-1.0>,
  "source_ip": "<attacker_ip_or_empty>",
  "target_host": "<agent_name_or_empty>",
  "mitre_technique": "<T1234.001_or_empty>",
  "reasoning": "<one concise sentence>"
}}"""

        # ── Step 3: Call LLM (cascade: Cerebras → Groq → Gemini) ─────────────
        decision = await _llm_decide(prompt)
        if decision is None:
            logger.warning("orchestrator.phase3.llm_failed",
                           incident_id=incident_id, rule_id=rule_id)
            return {
                "incident_id": incident_id,
                "phase":       "phase3_llm_failed",
                "dispatch":    {"executed": False, "reason": "llm_unavailable"},
            }

        logger.info("orchestrator.phase3.decision",
                    incident_id=incident_id,
                    rule_id=rule_id,
                    action=decision.get("action"),
                    confidence=decision.get("confidence"),
                    reasoning=decision.get("reasoning", "")[:100])

        # ── Step 4: Validate ──────────────────────────────────────────────────
        action     = decision.get("action", "no_action")
        confidence = float(decision.get("confidence", 0.0))
        target     = decision.get("target_host", agent_name) or agent_name
        src        = decision.get("source_ip", src_ip) or src_ip

        if action == "no_action" or action not in _PHASE3_ALLOWED_PLAYBOOKS:
            return {
                "incident_id": incident_id,
                "phase":       "phase3_llm",
                "decision":    decision,
                "dispatch":    {"executed": False,
                                "reason": f"no_action_or_invalid_playbook: {action}"},
            }

        # Safety guards
        if src and (src in ("127.0.0.1", "::1") or src.startswith("10.60.")):
            return {
                "incident_id": incident_id,
                "phase":       "phase3_llm",
                "decision":    decision,
                "dispatch":    {"executed": False,
                                "reason": f"safety_guard: protected_ip {src}"},
            }

        if confidence < 0.6:
            return {
                "incident_id": incident_id,
                "phase":       "phase3_llm",
                "decision":    decision,
                "dispatch":    {"executed": False,
                                "reason": f"low_confidence: {confidence}"},
            }

        if PHASE3_DRY_RUN:
            logger.info("orchestrator.phase3.dry_run",
                        playbook=action, target=target, src=src)
            return {
                "incident_id": incident_id,
                "phase":       "phase3_llm_dry_run",
                "decision":    decision,
                "dispatch":    {"executed": False, "reason": "dry_run",
                                "would_run": action, "on": target},
            }

        # ── Step 5: Execute ───────────────────────────────────────────────────
        extra_vars = extract_vars_from_alert(alert)
        extra_vars.update({
            "incident_id": incident_id,
            "severity":    decision.get("severity", "high"),
            "source_ip":   src,
            "target_hosts": target,
            "dry_run":     False,
        })

        try:
            result = await self._trigger.run_playbook(
                playbook=action,
                extra_vars=extra_vars,
            )
            # Write to DB
            try:
                with get_db() as db:
                    db.add(Incident(
                        id=incident_id,
                        wazuh_alert_id=str(alert.get("id", "")),
                        rule_id=int(rule_id) if rule_id.isdigit() else 0,
                        rule_description=alert.get("rule", {}).get("description"),
                        severity=SEVERITY_MAP.get(decision.get("severity", "high"),
                                                  SeverityLevel.HIGH),
                        status=IncidentStatus.RESPONDING,
                        source_ip=src,
                        analysis=decision.get("reasoning", ""),
                        recommended_action=action,
                        confidence_score=confidence,
                        playbook_executed=action,
                        playbook_result=result,
                        alert_data=alert,
                    ))
            except Exception as db_exc:
                logger.warning("orchestrator.phase3.db_failed", error=str(db_exc))

            return {
                "incident_id": incident_id,
                "phase":       "phase3_llm",
                "decision":    decision,
                "dispatch":    {"executed": True, "playbook": action,
                                "result": result},
            }
        except Exception as exc:
            logger.error("orchestrator.phase3.execution_failed", error=str(exc))
            return {
                "incident_id": incident_id,
                "phase":       "phase3_llm",
                "decision":    decision,
                "dispatch":    {"executed": False, "reason": f"execution_failed: {exc}"},
            }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_src_ip(alert: dict) -> str:
    data = alert.get("data", {}) or {}
    win  = (data.get("win") or {}).get("eventdata") or {}
    return (
        data.get("srcip") or data.get("src_ip")
        or win.get("ipAddress") or win.get("ipaddress") or ""
    )


async def _llm_decide(prompt: str) -> dict | None:
    """
    Single-shot LLM call with Cerebras→Groq→Gemini cascade.
    Returns parsed JSON dict or None if all providers fail.
    """
    import os, re, requests as _req

    providers = [
        {
            "name":    "cerebras",
            "url":     "https://api.cerebras.ai/v1/chat/completions",
            "key":     os.getenv("CEREBRAS_API_KEY", ""),
            "model":   os.getenv("CEREBRAS_MODEL", "qwen-3-235b-a22b-instruct-2507"),
        },
        {
            "name":    "groq",
            "url":     "https://api.groq.com/openai/v1/chat/completions",
            "key":     os.getenv("GROQ_API_KEY", ""),
            "model":   os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
        },
        {
            "name":    "gemini",
            "url":     "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            "key":     os.getenv("GEMINI_API_KEY", ""),
            "model":   os.getenv("GEMINI_MODEL", "gemini-2.5-flash").removeprefix("gemini/"),
        },
    ]

    for p in providers:
        if not p["key"]:
            continue
        try:
            resp = _req.post(
                p["url"],
                headers={"Authorization": f"Bearer {p['key']}",
                         "Content-Type": "application/json"},
                json={
                    "model":       p["model"],
                    "messages":    [{"role": "user", "content": prompt}],
                    "temperature": 0,
                    "max_tokens":  512,
                },
                timeout=30,
            )
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"].strip()
            # Extract JSON block
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if m:
                return json.loads(m.group(0))
        except Exception as exc:
            logger.warning("orchestrator.phase3.llm_provider_failed",
                           provider=p["name"], error=str(exc)[:100])
            continue

    return None
