import httpx
import json
import uuid
import structlog
from datetime import datetime, timedelta
from ai_agents.agents.base_agent import BaseAgent
from ai_agents.integrations.redis_manager import get_redis
from ai_agents.database.db_manager import get_db
from ai_agents.database.models import ThreatIntelCache
from ai_agents.config import get_settings

logger = structlog.get_logger()

class ThreatIntelAgent(BaseAgent):
    name = "threat_intel"

    async def run(self, input_data: dict) -> dict:
        mitre_techniques = input_data.get("mitre_techniques", [])
        iocs = input_data.get("iocs", {})
        intel = {"mitre": [], "nvd_cves": [], "ip_reputation": []}

        for technique in mitre_techniques[:5]:
            cached = get_redis().get(f"mitre:{technique}")
            if cached:
                intel["mitre"].append(cached)
                continue
            data = {"technique_id": technique, "source": "mitre_cache_miss"}
            intel["mitre"].append(data)
            get_redis().set(f"mitre:{technique}", data, ttl=86400)

        for ip in iocs.get("ip_addresses", [])[:3]:
            cached = get_redis().get(f"ip_rep:{ip}")
            if cached:
                intel["ip_reputation"].append(cached)
            else:
                data = {"ip": ip, "source": "local", "reputation": "unknown"}
                intel["ip_reputation"].append(data)
                get_redis().set(f"ip_rep:{ip}", data, ttl=3600)

        return intel
