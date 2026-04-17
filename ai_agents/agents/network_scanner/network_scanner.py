import asyncio
import structlog
from ai_agents.agents.base_agent import BaseAgent
from ai_agents.tools.suricata_consumer import read_recent_alerts

logger = structlog.get_logger()

class NetworkScannerAgent(BaseAgent):
    name = "network_scanner"

    async def run(self, input_data: dict) -> dict:
        alerts = await read_recent_alerts(limit=100)
        
        src_ips = {}
        for alert in alerts:
            ip = alert.get("src_ip")
            if ip:
                src_ips[ip] = src_ips.get(ip, 0) + 1

        top_sources = sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_suricata_alerts": len(alerts),
            "unique_source_ips": len(src_ips),
            "top_sources": [{"ip": ip, "alert_count": count} for ip, count in top_sources],
        }
