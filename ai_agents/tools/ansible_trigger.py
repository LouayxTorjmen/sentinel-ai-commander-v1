import httpx
import structlog
from typing import Optional
from ai_agents.config import get_settings

logger = structlog.get_logger()

class AnsibleTrigger:
    def __init__(self):
        s = get_settings()
        self.base_url = f"http://{s.ansible_runner_host}:{s.ansible_runner_port}"

    async def run_playbook(self, playbook: str, extra_vars: dict, tags: Optional[list] = None) -> dict:
        async with httpx.AsyncClient(timeout=120) as client:
            try:
                payload = {"playbook": playbook, "extra_vars": extra_vars}
                if tags:
                    payload["tags"] = tags
                resp = await client.post(f"{self.base_url}/run", json=payload)
                result = resp.json()
                logger.info("ansible.playbook.executed", playbook=playbook, status=result.get("status"), rc=result.get("rc"))
                return result
            except Exception as e:
                logger.error("ansible.trigger.failed", playbook=playbook, error=str(e))
                return {"status": "error", "error": str(e), "rc": -1}

    async def health(self) -> bool:
        async with httpx.AsyncClient(timeout=5) as client:
            try:
                resp = await client.get(f"{self.base_url}/health")
                return resp.status_code == 200
            except Exception:
                return False
