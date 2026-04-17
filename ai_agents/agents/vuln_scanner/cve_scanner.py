import httpx
import structlog
from ai_agents.agents.base_agent import BaseAgent
from ai_agents.integrations.redis_manager import get_redis
from ai_agents.config import get_settings

logger = structlog.get_logger()

class CVEScannerAgent(BaseAgent):
    name = "vuln_scanner"

    async def run(self, input_data: dict) -> dict:
        keywords = input_data.get("keywords", [])
        cves = []
        s = get_settings()

        for keyword in keywords[:3]:
            cache_key = f"nvd:{keyword}"
            cached = get_redis().get(cache_key)
            if cached:
                cves.extend(cached)
                continue

            try:
                params = {"keywordSearch": keyword, "resultsPerPage": 5}
                headers = {}
                if s.nvd_api_key:
                    headers["apiKey"] = s.nvd_api_key

                async with httpx.AsyncClient(timeout=15) as client:
                    resp = await client.get(s.nvd_api_base_url, params=params, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        items = data.get("vulnerabilities", [])
                        results = []
                        for item in items:
                            cve = item.get("cve", {})
                            metrics = cve.get("metrics", {})
                            cvss_data = (
                                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                                if metrics.get("cvssMetricV31")
                                else metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
                                if metrics.get("cvssMetricV2")
                                else {}
                            )
                            descriptions = cve.get("descriptions", [])
                            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
                            results.append({
                                "cve_id": cve.get("id"),
                                "description": desc[:300],
                                "cvss_score": cvss_data.get("baseScore"),
                                "severity": cvss_data.get("baseSeverity"),
                            })
                        get_redis().set(cache_key, results, ttl=3600)
                        cves.extend(results)
            except Exception as e:
                logger.error("cve_scanner.nvd.failed", keyword=keyword, error=str(e))

        return {"cves": cves, "total": len(cves)}
