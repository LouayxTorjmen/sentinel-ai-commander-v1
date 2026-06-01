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
                rc = result.get("rc")
                status = result.get("status")
                summary = result.get("summary", {})
                changed_tasks = result.get("changed_tasks", [])
                failed_tasks = result.get("failed_tasks", [])

                logger.info("ansible.playbook.executed",
                            playbook=playbook, rc=rc, status=status,
                            changed=summary.get("changed", 0),
                            failed=summary.get("failed", 0))

                # Log each meaningful task outcome for SOC visibility
                for task in changed_tasks:
                    outcome = task.get("outcome") or task.get("task", "")
                    if outcome:
                        logger.info("playbook.task.changed",
                                    playbook=playbook,
                                    host=task.get("host", ""),
                                    task=task.get("task", ""),
                                    outcome=outcome[:200])

                for task in failed_tasks:
                    logger.warning("playbook.task.failed",
                                   playbook=playbook,
                                   host=task.get("host", ""),
                                   task=task.get("task", ""),
                                   error=task.get("error", "")[:200])

                if summary.get("outcomes"):
                    logger.info("playbook.outcome_summary",
                                playbook=playbook,
                                actions=summary["outcomes"])

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
