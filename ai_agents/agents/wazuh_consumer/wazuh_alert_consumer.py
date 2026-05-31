import asyncio
from datetime import datetime, timezone, timedelta
import structlog
from ai_agents.tools.wazuh_client import WazuhClient as WazuhAPIClient
from ai_agents.integrations.redis_manager import get_redis
from ai_agents.config import get_settings
from ai_agents.agents.ansible_dispatch.ansible_dispatch_agent import STATIC_RULE_MAP

logger = structlog.get_logger()

ALERT_CHANNEL = "sentinel:alerts"
POLL_INTERVAL = 15

async def consume_wazuh_alerts():
    client = WazuhAPIClient()
    redis = get_redis()
    seen_ids = set()

    logger.info("wazuh_consumer.started", poll_interval=POLL_INTERVAL)

    while True:
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            # Only fetch alerts newer than last poll window to avoid seen_ids poisoning on restart
            _since = (datetime.now(timezone.utc) - timedelta(seconds=POLL_INTERVAL + 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
            alerts = await loop.run_in_executor(None, lambda: client.get_alerts(limit=500, level_gte=5, timestamp_gte=_since))
            new_alerts = []
            for alert in alerts:
                alert_id = alert.get("id") or alert.get("_id")
                if alert_id and alert_id not in seen_ids:
                    seen_ids.add(alert_id)
                    new_alerts.append(alert)

            if new_alerts:
                # Prioritize actionable alerts: static-map rules and high-severity
                # go to the front so the single-threaded orchestrator reaches them
                # before low-value noise (FIM churn, dpkg, etc.).
                def _priority(a):
                    rule = a.get("rule") or {}
                    rid = str(rule.get("id", ""))
                    try:
                        lvl = int(rule.get("level", 0))
                    except (TypeError, ValueError):
                        lvl = 0
                    in_map = rid in STATIC_RULE_MAP
                    # Lower sort key = processed first
                    return (0 if in_map else 1, -lvl)
                new_alerts.sort(key=_priority)
                logger.info("wazuh_consumer.new_alerts", count=len(new_alerts))
                for alert in new_alerts:
                    redis.publish(ALERT_CHANNEL, alert)

            if len(seen_ids) > 10000:
                seen_ids = set(list(seen_ids)[-5000:])

        except Exception as e:
            logger.error("wazuh_consumer.error", error=str(e))

        await asyncio.sleep(POLL_INTERVAL)
