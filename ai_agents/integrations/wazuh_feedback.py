"""
ai_agents/integrations/wazuh_feedback.py

Emits structured JSON decision events to a file the Wazuh manager
monitors as a localfile. Each emitted event becomes a Wazuh alert
(rules 100501-100507) visible in the dashboard, linked to the original
trigger via incident_id.

Drop this file into ai_agents/integrations/wazuh_feedback.py and import
from the dispatcher, orchestrator, and runner-call sites.

Usage:
    from ai_agents.integrations.wazuh_feedback import emit_feedback

    emit_feedback(
        phase="decision_made",
        incident_id=incident_id,
        triggering_rule_id="100231",
        target_agent="srv-ftp",
        playbook="file_quarantine_response",
        decision_source="static_map",
        ai_severity="high",
        confidence=0.95,
    )
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

# Where to write. Default matches the Wazuh manager's expected localfile path.
# Override with SENTINEL_FEEDBACK_PATH for tests.
FEEDBACK_PATH = Path(os.getenv(
    "SENTINEL_FEEDBACK_PATH",
    "/var/ossec/logs/sentinel_ai_decisions.json",
))

# Process-local write lock so multiple coroutines don't interleave bytes
# in the same JSON line. The cost is negligible — we only hold it for
# the duration of a single write().
_write_lock = threading.Lock()


def _now_iso() -> str:
    """RFC3339 timestamp in UTC, second precision."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def emit_feedback(
    *,
    phase: str,
    incident_id: str = "",
    triggering_rule_id: str | int = "",
    triggering_level: int | str = "",
    target_agent: str = "",
    playbook: str = "",
    decision_source: str = "",
    ai_severity: str = "",
    confidence: float | str = "",
    skip_reason: str = "",
    no_action_reason: str = "",
    failure_reason: str = "",
    ansible_rc: int | str = "",
    tasks_ok: int | str = "",
    tasks_changed: int | str = "",
    tasks_failed: int | str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    """Write a single JSON line to the feedback file.

    Never raises — even if the file is unwriteable, we silently swallow
    the error so feedback emission never breaks the dispatch chain.
    A failure to write feedback is at worst a missing dashboard entry;
    it must NEVER prevent an actual response from running.
    """
    payload: dict[str, Any] = {
        "event":              "sentinel_ai",
        "timestamp":          _now_iso(),
        "phase":              phase,
        "incident_id":        incident_id,
        "triggering_rule_id": str(triggering_rule_id),
        "triggering_level":   triggering_level,
        "target_agent":       target_agent,
        "playbook":           playbook,
        "decision_source":    decision_source,
        "ai_severity":        ai_severity,
        "confidence":         confidence,
        "skip_reason":        skip_reason,
        "no_action_reason":   no_action_reason,
        "failure_reason":     failure_reason,
        "ansible_rc":         ansible_rc,
        "tasks_ok":           tasks_ok,
        "tasks_changed":      tasks_changed,
        "tasks_failed":       tasks_failed,
    }
    if extra:
        payload.update(extra)

    line = json.dumps(payload, ensure_ascii=False) + "\n"

    try:
        FEEDBACK_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _write_lock:
            with FEEDBACK_PATH.open("a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
    except OSError:
        # Silent — feedback is best-effort, never block dispatch.
        pass


# ─── Convenience helpers — one function per phase ────────────────────

def feedback_received(*, incident_id, rule_id, level, agent) -> None:
    emit_feedback(
        phase="dispatch_received",
        incident_id=incident_id,
        triggering_rule_id=rule_id,
        triggering_level=level,
        target_agent=agent,
    )


def feedback_skipped(*, incident_id, rule_id, agent, reason) -> None:
    emit_feedback(
        phase="dispatch_skipped",
        incident_id=incident_id,
        triggering_rule_id=rule_id,
        target_agent=agent,
        skip_reason=reason,
    )


def feedback_decision(*, incident_id, rule_id, agent, playbook,
                      decision_source, ai_severity, confidence) -> None:
    emit_feedback(
        phase="decision_made",
        incident_id=incident_id,
        triggering_rule_id=rule_id,
        target_agent=agent,
        playbook=playbook,
        decision_source=decision_source,
        ai_severity=ai_severity,
        confidence=confidence,
    )


def feedback_dry_run(*, incident_id, rule_id, agent, playbook) -> None:
    emit_feedback(
        phase="dry_run_executed",
        incident_id=incident_id,
        triggering_rule_id=rule_id,
        target_agent=agent,
        playbook=playbook,
    )


def feedback_executed(*, incident_id, rule_id, agent, playbook,
                      rc, ok=0, changed=0, failed=0) -> None:
    emit_feedback(
        phase="playbook_executed",
        incident_id=incident_id,
        triggering_rule_id=rule_id,
        target_agent=agent,
        playbook=playbook,
        ansible_rc=rc,
        tasks_ok=ok,
        tasks_changed=changed,
        tasks_failed=failed,
    )


def feedback_failed(*, incident_id, rule_id, agent, playbook, reason) -> None:
    emit_feedback(
        phase="playbook_failed",
        incident_id=incident_id,
        triggering_rule_id=rule_id,
        target_agent=agent,
        playbook=playbook,
        failure_reason=reason,
    )


def feedback_no_action(*, incident_id, rule_id, agent, reason) -> None:
    emit_feedback(
        phase="no_action",
        incident_id=incident_id,
        triggering_rule_id=rule_id,
        target_agent=agent,
        no_action_reason=reason,
    )
