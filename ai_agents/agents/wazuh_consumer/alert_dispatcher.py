"""
Subscribe to Redis ALERT_CHANNEL and dispatch every new alert to the
OrchestratorAgent for full triage (classify -> enrich -> CVE map ->
incident -> playbook routing).

Pairs with wazuh_alert_consumer (publisher). Started as a background
asyncio task from main.py.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import structlog

from ai_agents.integrations.redis_manager import get_redis

logger = structlog.get_logger()

ALERT_CHANNEL = "sentinel:alerts"

# Skip alerts below this rule.level — matches consumer's own filter
# (level_gte=5) but we double-check at dispatch time so a future
# consumer change can't accidentally flood the orchestrator.
DISPATCH_MIN_LEVEL = int(os.getenv("DISPATCH_MIN_LEVEL", "5"))

# Per (rule_id, agent_name) dedup window. The same rule firing on the
# same agent within this many seconds will only trigger orchestrator
# once. Defends against burst floods (e.g. nmap scan firing 30
# ET SCAN MSSQL alerts in 5 seconds — orchestrator only needs to see
# one to triage).
DISPATCH_DEDUP_WINDOW_S = float(os.getenv("DISPATCH_DEDUP_WINDOW_S", "60"))

# Set to "1" to bypass the noise filter (e.g. for testing all rules)
DISABLE_NOISE_FILTER = os.getenv("DISPATCH_DISABLE_NOISE_FILTER", "0") == "1"

# Rules with no SOC value on this lab — desktop / dpkg / systemd noise
HARD_SKIP_RULES = {
    40704,   # systemd unit failure (desktop app crashes)
    2902,    # dpkg package installed (workstation noise)
    2904,    # dpkg package removed (workstation noise)
}

# FIM rules that need path-based filtering (real changes still pass)
_FIM_RULES = {550, 553, 554}

# Substring patterns for FIM paths that are KNOWN noise. If a FIM
# alert's syscheck.path contains any of these, skip dispatch.
_FIM_NOISE_PATTERNS = (
    # User desktop / session state
    "/.config/", "/.local/", "/.cache/", "/.xsession-errors",
    "/.gvfs-metadata/", "/.mozilla/", "/.thunderbird/",
    "/.dbus/", "/run/user/",
    # Snap apps churn
    "/snap/",
    # Print spooler + ansible runs
    "/etc/cups/", "/tmp/ansible_", "/tmp/.X", "/tmp/systemd-",
    # Package manager tempdirs and metadata (dnf/yum/apt/rpm)
    "/tmp/tmpdir.", "/repodata/",
    "/var/cache/apt/", "/var/cache/dnf/", "/var/cache/yum/",
    "/var/lib/dnf/", "/var/lib/apt/", "/var/lib/rpm/",
    # systemd transient drop-ins
    "/run/systemd/",
)

# Tracks (rule_id, agent_name) -> last dispatch timestamp (monotonic)
_recent_dispatches: dict = {}


def _is_fim_noise(alert: dict) -> bool:
    """Return True if a FIM alert path matches a known noise pattern."""
    syscheck = alert.get("syscheck") or alert.get("data", {}).get("syscheck") or {}
    path = (syscheck.get("path") or "").lower()
    if not path:
        return False
    return any(pat in path for pat in _FIM_NOISE_PATTERNS)


def _should_dispatch(alert: dict, level: int) -> tuple[bool, str]:
    """Decide whether an alert should reach the orchestrator.

    Returns (allow, reason). reason is empty when allowed; populated
    with a short tag when skipped (for logging).
    """
    rule = alert.get("rule") or {}
    try:
        rule_id = int(rule.get("id", 0))
    except (TypeError, ValueError):
        rule_id = 0
    agent_name = (alert.get("agent") or {}).get("name") or ""

    if not DISABLE_NOISE_FILTER:
        if rule_id in HARD_SKIP_RULES:
            return False, f"hard_skip_rule_{rule_id}"
        if rule_id in _FIM_RULES and _is_fim_noise(alert):
            return False, "fim_path_noise"

    # Per (rule_id, agent_name) dedup
    import time
    key = (rule_id, agent_name)
    now = time.monotonic()
    last = _recent_dispatches.get(key)
    if last is not None and now - last < DISPATCH_DEDUP_WINDOW_S:
        return False, "dedup"
    _recent_dispatches[key] = now

    # Periodic cleanup of stale entries to avoid unbounded memory growth
    if len(_recent_dispatches) > 5000:
        cutoff = now - DISPATCH_DEDUP_WINDOW_S * 2
        _recent_dispatches.clear()  # cheap reset; data is just timestamps
        _recent_dispatches[key] = now
        del cutoff

    return True, ""


def _decode(raw: Any) -> dict | None:
    """Decode a redis pubsub payload into an alert dict, or None on failure."""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None
    return None


async def dispatch_alerts(orchestrator) -> None:
    """Background task: forever consume Redis pubsub messages and
    dispatch each alert to the orchestrator."""
    redis = get_redis()
    pubsub = redis.subscribe(ALERT_CHANNEL)
    logger.info("alert_dispatcher.started", channel=ALERT_CHANNEL,
                min_level=DISPATCH_MIN_LEVEL)

    loop = asyncio.get_event_loop()

    def _next_message():
        # Blocking call; runs in executor.
        # timeout lets us yield control periodically and is also how we
        # respond to cancellation cleanly.
        return pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)

    while True:
        try:
            msg = await loop.run_in_executor(None, _next_message)
            if not msg:
                # No message in window — keep looping
                await asyncio.sleep(0)
                continue

            alert = _decode(msg.get("data"))
            if alert is None:
                logger.warning("alert_dispatcher.decode_failed",
                               raw_type=type(msg.get("data")).__name__)
                continue

            level = (alert.get("rule") or {}).get("level", 0)
            try:
                level = int(level)
            except (TypeError, ValueError):
                level = 0
            if level < DISPATCH_MIN_LEVEL:
                logger.debug("alert_dispatcher.skip_low_level",
                             level=level, min_level=DISPATCH_MIN_LEVEL)
                continue

            allow, reason = _should_dispatch(alert, level)
            if not allow:
                logger.debug("alert_dispatcher.skip",
                             reason=reason,
                             rule_id=(alert.get("rule") or {}).get("id"),
                             agent=(alert.get("agent") or {}).get("name"))
                continue

            try:
                result = await orchestrator.process_alert(alert)
                logger.info(
                    "alert_dispatcher.processed",
                    rule_id=(alert.get("rule") or {}).get("id"),
                    level=level,
                    incident_id=result.get("incident_id"),
                    severity=result.get("severity"),
                    dispatched=result.get("dispatch", {}).get("executed"),
                )
            except Exception as exc:
                logger.warning("alert_dispatcher.process_failed",
                               error=str(exc),
                               rule_id=(alert.get("rule") or {}).get("id"))

        except asyncio.CancelledError:
            logger.info("alert_dispatcher.cancelled")
            try:
                pubsub.unsubscribe(ALERT_CHANNEL)
                pubsub.close()
            except Exception:
                pass
            raise
        except Exception as exc:
            # Don't let the loop die on transient errors
            logger.error("alert_dispatcher.loop_error", error=str(exc))
            await asyncio.sleep(2)
