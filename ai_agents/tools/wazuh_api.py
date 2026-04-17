import httpx
import structlog
from typing import Optional
from tenacity import retry, stop_after_attempt, wait_exponential
from ai_agents.config import get_settings

logger = structlog.get_logger()

class WazuhAPIClient:
    def __init__(self):
        s = get_settings()
        self.base_url = f"https://{s.wazuh_manager_host}:55000"
        self.user = s.wazuh_api_user
        self.password = s.wazuh_api_password
        self._token: Optional[str] = None
        self._client = httpx.AsyncClient(verify=False, timeout=30)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def authenticate(self) -> str:
        resp = await self._client.post(
            f"{self.base_url}/security/user/authenticate",
            auth=(self.user, self.password),
        )
        resp.raise_for_status()
        self._token = resp.json()["data"]["token"]
        return self._token

    async def _headers(self) -> dict:
        if not self._token:
            await self.authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    async def get_alerts(self, limit: int = 100, level: int = 3) -> list:
        try:
            headers = await self._headers()
            resp = await self._client.get(
                f"{self.base_url}/alerts",
                headers=headers,
                params={"limit": limit, "sort": "-timestamp", "level": level},
            )
            if resp.status_code == 401:
                await self.authenticate()
                headers = await self._headers()
                resp = await self._client.get(
                    f"{self.base_url}/alerts",
                    headers=headers,
                    params={"limit": limit, "sort": "-timestamp", "level": level},
                )
            resp.raise_for_status()
            return resp.json().get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("wazuh.get_alerts.failed", error=str(e))
            return []

    async def get_agents(self) -> list:
        try:
            headers = await self._headers()
            resp = await self._client.get(f"{self.base_url}/agents", headers=headers)
            resp.raise_for_status()
            return resp.json().get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("wazuh.get_agents.failed", error=str(e))
            return []

    async def close(self):
        await self._client.aclose()
