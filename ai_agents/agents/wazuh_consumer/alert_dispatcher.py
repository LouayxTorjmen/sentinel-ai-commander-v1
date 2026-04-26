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
