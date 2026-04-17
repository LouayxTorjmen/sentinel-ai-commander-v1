import asyncio
import structlog
from ai_agents.tools.wazuh_client import WazuhClient as WazuhAPIClient
from ai_agents.integrations.redis_manager import get_redis
from ai_agents.config import get_settings

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
            alerts = await loop.run_in_executor(None, lambda: client.get_alerts(limit=50, level_gte=5))
            new_alerts = []
            for alert in alerts:
                alert_id = alert.get("id") or alert.get("_id")
                if alert_id and alert_id not in seen_ids:
                    seen_ids.add(alert_id)
                    new_alerts.append(alert)

            if new_alerts:
                logger.info("wazuh_consumer.new_alerts", count=len(new_alerts))
                for alert in new_alerts:
                    redis.publish(ALERT_CHANNEL, alert)

            if len(seen_ids) > 10000:
                seen_ids = set(list(seen_ids)[-5000:])

        except Exception as e:
            logger.error("wazuh_consumer.error", error=str(e))

        await asyncio.sleep(POLL_INTERVAL)
