import time
import uuid
import structlog
from abc import ABC, abstractmethod
from typing import Any, Optional
from ai_agents.database.db_manager import get_db
from ai_agents.database.models import AgentActivity

logger = structlog.get_logger()

class BaseAgent(ABC):
    name: str = "base_agent"

    def __init__(self):
        self.logger = structlog.get_logger().bind(agent=self.name)

    @abstractmethod
    async def run(self, input_data: dict) -> dict:
        pass

    async def execute(self, input_data: dict) -> dict:
        start = time.monotonic()
        activity_id = str(uuid.uuid4())
        incident_id = input_data.get("incident_id")
        result = {}
        success = 1
        error_msg = None

        try:
            self.logger.info("agent.start", incident_id=incident_id)
            result = await self.run(input_data)
            self.logger.info("agent.complete", incident_id=incident_id)
        except Exception as e:
            success = 0
            error_msg = str(e)
            self.logger.error("agent.error", incident_id=incident_id, error=error_msg)
            result = {"error": error_msg, "agent": self.name}
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            try:
                with get_db() as db:
                    db.add(AgentActivity(
                        id=activity_id,
                        agent_name=self.name,
                        incident_id=incident_id,
                        action="run",
                        input_data=input_data,
                        output_data=result,
                        duration_ms=duration_ms,
                        success=success,
                        error_message=error_msg,
                    ))
            except Exception as db_err:
                self.logger.warning("agent.activity.log_failed", error=str(db_err))

        return result
