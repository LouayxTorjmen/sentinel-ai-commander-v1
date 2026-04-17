import uvicorn
from ai_agents.config import get_settings

if __name__ == "__main__":
    s = get_settings()
    uvicorn.run(
        "ai_agents.main:app",
        host="0.0.0.0",
        port=s.ai_agents_port,
        reload=True,
        log_level=s.log_level.lower(),
    )
