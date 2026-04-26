import asyncio
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict

from ai_agents.database.db_manager import init_db, get_db
from ai_agents.database.models import Incident
from ai_agents.agents.orchestrator.orchestrator import OrchestratorAgent
from ai_agents.agents.wazuh_consumer.wazuh_alert_consumer import consume_wazuh_alerts
from ai_agents.agents.wazuh_consumer.alert_dispatcher import dispatch_alerts
from ai_agents.agents.network_scanner.network_scanner import NetworkScannerAgent
from ai_agents.agents.wazuh_suricata.wazuh_suricata_agent import WazuhSuricataAgent
from ai_agents.integrations.redis_manager import get_redis
from ai_agents.config import get_settings
from ai_agents.rag.chat_engine import ChatEngine
from ai_agents.ml.model_manager import ModelManager
from ai_agents.llm.fallback import get_llm_provider
from ai_agents.discovery.auto_discovery import AutoDiscoveryAgent, discovery_loop

logger = structlog.get_logger()
_consumer_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _consumer_task
    logger.info("sentinel_ai.startup")
    init_db()
    _consumer_task = asyncio.create_task(consume_wazuh_alerts())
    _dispatcher_task = asyncio.create_task(dispatch_alerts(orchestrator))
    # Pull Ollama model in background
    asyncio.create_task(_ensure_ollama_model())
    # Start auto-discovery loop
    asyncio.create_task(discovery_loop(discovery_agent))
    yield
    if _consumer_task:
        _consumer_task.cancel()
    logger.info("sentinel_ai.shutdown")


async def _ensure_ollama_model():
    """Pull Ollama model on startup if fallback is enabled."""
    try:
        provider = get_llm_provider()
        provider._gemini_available()  # triggers pull if needed
    except Exception as e:
        logger.warning("ollama.model_pull_background_failed", error=str(e))


app = FastAPI(
    title="SENTINEL-AI Commander",
    description="PhD-level AI-powered SOC automation with RAG chat, ML anomaly detection, and offline resilience",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = OrchestratorAgent()
network_scanner = NetworkScannerAgent()
correlation_agent = WazuhSuricataAgent(config={}, redis_manager=None)
chat_engine = ChatEngine()
model_manager = ModelManager()
discovery_agent = AutoDiscoveryAgent()


# ═════════════════════════════════════════════════════════════════════════════
#  EXISTING ENDPOINTS (unchanged from v1)
# ═════════════════════════════════════════════════════════════════════════════

class AlertRequest(BaseModel):
    alert: dict
    incident_id: Optional[str] = None


@app.get("/health")
async def health():
    redis_ok = get_redis().ping()
    llm_health = get_llm_provider().health()
    ml_health = model_manager.health()
    return {
        "status": "ok",
        "redis": redis_ok,
        "service": "sentinel-ai",
        "version": "2.0.0",
        "llm": llm_health,
        "ml": ml_health,
    }


@app.post("/analyze")
async def analyze_alert(req: AlertRequest):
    try:
        # ML prediction (if trained)
        ml_result = model_manager.predict_alert(req.alert)
        result = await orchestrator.process_alert(req.alert)
        result["ml_prediction"] = ml_result
        return result
    except Exception as e:
        logger.error("api.analyze.failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents")
async def list_incidents(limit: int = 20, severity: Optional[str] = None):
    try:
        with get_db() as db:
            q = db.query(Incident).order_by(Incident.created_at.desc())
            if severity:
                q = q.filter(Incident.severity == severity)
            incidents = q.limit(limit).all()
            return [
                {
                    "id": i.id,
                    "rule_description": i.rule_description,
                    "severity": i.severity,
                    "status": i.status,
                    "source_ip": i.source_ip,
                    "mitre_techniques": i.mitre_techniques,
                    "confidence_score": i.confidence_score,
                    "playbook_executed": i.playbook_executed,
                    "created_at": str(i.created_at),
                }
                for i in incidents
            ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    cached = get_redis().get(f"incident:{incident_id}")
    if cached:
        return cached
    try:
        with get_db() as db:
            incident = db.query(Incident).filter(Incident.id == incident_id).first()
            if not incident:
                raise HTTPException(status_code=404, detail="Incident not found")
            return {"id": incident.id,
                "analysis": incident.analysis,
                "severity": incident.severity,
                "status": incident.status,
                "mitre_techniques": incident.mitre_techniques,
                "playbook_executed": incident.playbook_executed,
                "playbook_result": incident.playbook_result,
                "alert_data": incident.alert_data,
                "created_at": str(incident.created_at),
    }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/network/summary")
async def network_summary():
    result = await network_scanner.execute({})
    return result


@app.get("/stats")
async def stats():
    try:
        from ai_agents.tools.wazuh_client import WazuhClient
        wc = WazuhClient()

        # OpenSearch alert counts
        body = {
            "size": 0,
            "aggs": {
                "by_level": {"terms": {"field": "rule.level", "size": 20}},
                "by_agent": {"terms": {"field": "agent.name", "size": 20}},
            }
        }
        data = wc._indexer_request(
            "POST", "/wazuh-alerts-4.x-*/_search",
            json=body, headers={"Content-Type": "application/json"},
        )
        total_alerts = data.get("hits", {}).get("total", {}).get("value", 0)
        by_level = {str(b["key"]): b["doc_count"] for b in data.get("aggregations", {}).get("by_level", {}).get("buckets", [])}
        by_agent = {b["key"]: b["doc_count"] for b in data.get("aggregations", {}).get("by_agent", {}).get("buckets", [])}

        critical = sum(v for k, v in by_level.items() if int(k) >= 13)
        high = sum(v for k, v in by_level.items() if 10 <= int(k) <= 12)
        medium = sum(v for k, v in by_level.items() if 7 <= int(k) <= 9)
        low = sum(v for k, v in by_level.items() if int(k) < 7)

        # Archive counts
        arch = wc._indexer_request("POST", "/wazuh-archives-4.x-*/_count", json={"query": {"match_all": {}}}, headers={"Content-Type": "application/json"})
        archive_total = arch.get("count", 0)

        # PostgreSQL incidents
        db_total = 0
        try:
            with get_db() as db:
                db_total = db.query(Incident).count()
        except Exception:
            pass

        return {"total_incidents": total_alerts,
            "by_severity": {"critical": critical, "high": high, "medium": medium, "low": low},
            "by_level": by_level,
            "by_agent": by_agent,
            "archive_events": archive_total,
            "db_incidents": db_total,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/correlate")
async def correlate_alerts(time_window: int = 10, limit: int = 50):
    try:
        result = await correlation_agent.run({
            "mode": "correlate",
            "time_window_minutes": time_window,
            "limit": limit,
        })
        return result
    except Exception as e:
        logger.error("api.correlate.failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/correlate/health")
async def correlate_health():
    try:
        return await correlation_agent.run({"mode": "health"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/correlate/incidents")
async def list_correlated_incidents(limit: int = 20):
    try:
        from ai_agents.database.models import CorrelatedIncident
        with get_db() as db:
            rows = db.query(CorrelatedIncident).order_by(
                CorrelatedIncident.created_at.desc()
            ).limit(limit).all()
            return [
                {
                    "id": r.id,
                    "wazuh_rule": r.wazuh_rule,
                    "suricata_signature": r.suricata_signature,
                    "combined_severity": r.combined_severity,
                    "mitre_technique_id": r.mitre_technique_id,
                    "mitre_tactic": r.mitre_tactic,
                    "shared_ip": r.shared_ip,
                    "ansible_playbook": r.ansible_playbook,
                    "created_at": str(r.created_at),
                }
                for r in rows
            ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═════════════════════════════════════════════════════════════════════════════
#  NEW: RAG CHAT ENDPOINT (Point 2)
# ═════════════════════════════════════════════════════════════════════════════

class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = None
    preferred_provider: Optional[str] = None


@app.post("/chat")
async def chat(req: ChatRequest):
    """
    RAG-powered chat with persistent sessions.
    Pass session_id to continue a conversation, or omit to create a new one.
    """
    try:
        result = await chat_engine.chat(req.message, session_id=req.session_id, history=req.history, preferred_provider=req.preferred_provider)
        return result
    except Exception as e:
        logger.error("api.chat.failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/chat/sessions")
async def create_chat_session(title: Optional[str] = None):
    """Create a new chat session."""
    return chat_engine.create_session(title)


@app.get("/chat/sessions")
async def list_chat_sessions(limit: int = 20):
    """List all chat sessions."""
    return chat_engine.list_sessions(limit)


@app.get("/chat/sessions/{session_id}")
async def get_session_messages(session_id: str, limit: int = 50):
    """Get all messages in a session."""
    return chat_engine.get_session_messages(session_id, limit)


@app.delete("/chat/sessions/{session_id}")
async def delete_chat_session(session_id: str):
    """Delete a session and all its messages."""
    return chat_engine.delete_session(session_id)


class RenameRequest(BaseModel):
    title: str


@app.post("/chat/sessions/{session_id}/rename")
async def rename_chat_session(session_id: str, req: RenameRequest):
    """Rename a chat session."""
    try:
        with get_db() as db:
            from ai_agents.database.models import ChatSession
            session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
            session.title = req.title
        return {"session_id": session_id, "title": req.title}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═════════════════════════════════════════════════════════════════════════════
#  NEW: ML ENDPOINTS (Point 4)
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/ml/train")
async def ml_train():
    """Train ML models (Isolation Forest + Random Forest) from historical incidents."""
    try:
        result = model_manager.train_from_db()
        return result
    except Exception as e:
        logger.error("api.ml.train.failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/ml/predict")
async def ml_predict(req: AlertRequest):
    """Run ML prediction on a single alert."""
    try:
        result = model_manager.predict_alert(req.alert)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ml/health")
async def ml_health():
    """ML model health and readiness status."""
    return model_manager.health()


# ═════════════════════════════════════════════════════════════════════════════
#  NEW: LLM PROVIDER ENDPOINTS (Point 5)
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/llm/health")
async def llm_health():
    """LLM provider health — shows Groq/Ollama status."""
    return get_llm_provider().health()


# ═════════════════════════════════════════════════════════════════════════════
#  DOCUMENT VIEWER — fetch raw OpenSearch doc by ID
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/doc/{index}/{doc_id}")
async def get_document(index: str, doc_id: str):
    """Fetch a specific document from OpenSearch by index and ID."""
    try:
        from ai_agents.tools.wazuh_client import WazuhClient
        wc = WazuhClient()
        data = wc._indexer_request("GET", f"/{index}/_doc/{doc_id}")
        if data.get("found"):
            return {"found": True, "index": index, "id": doc_id, "source": data.get("_source", {})}
        return {"found": False, "index": index, "id": doc_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ═════════════════════════════════════════════════════════════════════════════
#  NEW: AUTO-DISCOVERY ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/discovery/scan")
async def trigger_discovery():
    """Manually trigger a network discovery scan."""
    try:
        result = await discovery_agent.discover_and_enroll()
        return result
    except Exception as e:
        logger.error("api.discovery.failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/discovery/hosts")
async def list_discovered_hosts():
    """List all discovered hosts and their Wazuh enrollment status."""
    return discovery_agent.get_all_hosts()


@app.get("/discovery/latest")
async def latest_discovery():
    """Get results of the most recent discovery scan."""
    result = discovery_agent.get_latest_results()
    if result:
        return result
    return {"status": "no_scan_yet", "message": "No discovery scan has run yet. POST /discovery/scan to trigger one."}


@app.get("/discovery/agents")
async def list_wazuh_agents():
    """List all currently enrolled Wazuh agents."""
    try:
        await discovery_agent.refresh_known_agents()
        return {
            "total": len(discovery_agent._known_agents),
            "agents": discovery_agent._known_agents,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


