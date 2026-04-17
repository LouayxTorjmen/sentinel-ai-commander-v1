import json
import asyncio
import aiofiles
import structlog
from typing import AsyncGenerator, Optional
from pathlib import Path

logger = structlog.get_logger()

EVE_LOG_PATH = Path("/var/log/suricata/eve.json")

async def tail_eve_log(path: Path = EVE_LOG_PATH) -> AsyncGenerator[dict, None]:
    """Async tail of Suricata EVE JSON log — yields one event dict per line."""
    if not path.exists():
        logger.warning("suricata.eve.not_found", path=str(path))
        while not path.exists():
            await asyncio.sleep(5)

    async with aiofiles.open(path, mode="r") as f:
        await f.seek(0, 2)  # seek to end
        while True:
            line = await f.readline()
            if not line:
                await asyncio.sleep(0.1)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                yield event
            except json.JSONDecodeError:
                logger.warning("suricata.eve.parse_error", line=line[:100])

async def read_recent_alerts(path: Path = EVE_LOG_PATH, limit: int = 50) -> list:
    """Read the last N alert events from eve.json."""
    alerts = []
    if not path.exists():
        return alerts
    try:
        async with aiofiles.open(path, mode="r") as f:
            lines = await f.readlines()
        for line in reversed(lines[-500:]):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alerts.append(event)
                    if len(alerts) >= limit:
                        break
            except json.JSONDecodeError:
                continue
    except Exception as e:
        logger.error("suricata.read_recent.failed", error=str(e))
    return alerts
