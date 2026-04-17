"""
RAG-powered Chat Engine with persistent sessions.

Each session maintains conversation history in PostgreSQL and builds
a rolling context summary so the LLM remembers previous exchanges
even across container restarts.
"""
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import dspy

from ai_agents.rag.retriever import RAGRetriever
from ai_agents.llm.fallback import get_lm, get_llm_provider
from ai_agents.database.db_manager import get_db
from ai_agents.database.models import ChatSession, ChatMessage

logger = logging.getLogger(__name__)


class SecurityChatSignature(dspy.Signature):
    """You are SENTINEL-AI, an intelligent SOC assistant. Follow these rules:

    1. If the message is a security question, answer it using the provided data context. Reference specific IPs, alerts, agents, timestamps, and MITRE techniques from the context.
    2. If the message is casual conversation (greetings, apologies, thanks, small talk, jokes, personal questions), respond naturally and conversationally like a friendly colleague. Do NOT force a security analysis. Do NOT reference the data context. Just chat normally.
    3. If the message is ambiguous, ask what the user needs help with.
    4. Never make up data. If the context has no relevant information, say so clearly.
    5. Use markdown formatting: **bold** for emphasis, bullet lists with - for multiple items, `code` for IPs/commands/technique IDs."""

    question: str = dspy.InputField(desc="User message - could be a security question OR casual conversation")
    context: str = dspy.InputField(desc="Retrieved security data from all sources. ONLY use this for security questions, ignore for casual chat.")
    conversation_summary: str = dspy.InputField(desc="Summary of previous conversation in this session")
    answer: str = dspy.OutputField(desc="Response - either a detailed security answer with data references, or a natural conversational reply for casual messages")
    confidence: str = dspy.OutputField(desc="For security answers: high/medium/low. For casual chat: n/a")
    sources_used: str = dspy.OutputField(desc="For security answers: comma-separated data sources. For casual chat: none")


class SummarySignature(dspy.Signature):
    """Summarize the conversation so far for context in future turns."""
    conversation: str = dspy.InputField(desc="Recent conversation messages")
    previous_summary: str = dspy.InputField(desc="Previous rolling summary")
    summary: str = dspy.OutputField(desc="Updated rolling summary of key topics, IPs, agents, incidents discussed")


class ChatEngine:
    """RAG chat engine with persistent sessions."""

    def __init__(self):
        self._retriever = RAGRetriever()
        self._chain = None
        self._summarizer = None
        self._lm = None

    def _ensure_chain(self):
        self._lm = None  # fetched per-request
        self._chain = dspy.ChainOfThought(SecurityChatSignature)
        self._summarizer = dspy.ChainOfThought(SummarySignature)

    # ── Session Management ────────────────────────────────────────────────

    def create_session(self, title: Optional[str] = None) -> Dict:
        session_id = str(uuid.uuid4())
        try:
            with get_db() as db:
                session = ChatSession(
                    id=session_id,
                    title=title or f"Session {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
                    summary="",
                )
                db.add(session)
            return {"session_id": session_id, "title": title}
        except Exception as e:
            logger.error("chat.create_session_failed: %s", e)
            return {"session_id": session_id, "title": title, "error": str(e)}

    def list_sessions(self, limit: int = 20) -> List[Dict]:
        try:
            with get_db() as db:
                sessions = db.query(ChatSession).order_by(
                    ChatSession.updated_at.desc()
                ).limit(limit).all()
                return [
                    {
                        "session_id": s.id,
                        "title": s.title,
                        "message_count": s.message_count,
                        "created_at": str(s.created_at),
                        "updated_at": str(s.updated_at),
                    }
                    for s in sessions
                ]
        except Exception as e:
            logger.error("chat.list_sessions_failed: %s", e)
            return []

    def get_session_messages(self, session_id: str, limit: int = 50) -> List[Dict]:
        try:
            with get_db() as db:
                messages = db.query(ChatMessage).filter(
                    ChatMessage.session_id == session_id
                ).order_by(ChatMessage.created_at.asc()).limit(limit).all()
                return [
                    {
                        "id": m.id,
                        "role": m.role,
                        "content": m.content,
                        "confidence": m.confidence,
                        "sources_used": m.sources_used,
                        "context_summary": m.context_summary,
                        "llm_provider": m.llm_provider,
                        "created_at": str(m.created_at),
                    }
                    for m in messages
                ]
        except Exception as e:
            logger.error("chat.get_messages_failed: %s", e)
            return []

    def delete_session(self, session_id: str) -> Dict:
        try:
            with get_db() as db:
                db.query(ChatMessage).filter(ChatMessage.session_id == session_id).delete()
                db.query(ChatSession).filter(ChatSession.id == session_id).delete()
            return {"deleted": True, "session_id": session_id}
        except Exception as e:
            return {"deleted": False, "error": str(e)}

    def _get_session_context(self, session_id: str) -> tuple:
        """Get rolling summary and recent messages for a session."""
        summary = ""
        recent_messages = []
        try:
            with get_db() as db:
                session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
                if session:
                    summary = session.summary or ""
                messages = db.query(ChatMessage).filter(
                    ChatMessage.session_id == session_id
                ).order_by(ChatMessage.created_at.desc()).limit(6).all()
                recent_messages = [
                    {"role": m.role, "content": m.content}
                    for m in reversed(messages)
                ]
        except Exception as e:
            logger.warning("chat.get_context_failed: %s", e)
        return summary, recent_messages

    def _save_message(self, session_id: str, role: str, content: str, **kwargs):
        try:
            with get_db() as db:
                db.add(ChatMessage(
                    id=str(uuid.uuid4()),
                    session_id=session_id,
                    role=role,
                    content=content,
                    confidence=kwargs.get("confidence"),
                    sources_used=kwargs.get("sources_used", []),
                    context_summary=kwargs.get("context_summary", {}),
                    llm_provider=kwargs.get("llm_provider"),
                ))
                session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
                if session:
                    session.message_count = (session.message_count or 0) + 1
                    session.updated_at = datetime.utcnow()
        except Exception as e:
            logger.warning("chat.save_message_failed: %s", e)

    def _update_summary(self, session_id: str, recent_messages: List[Dict], old_summary: str):
        """Update rolling summary every 4 messages."""
        try:
            if len(recent_messages) < 4:
                return
            conversation = "\n".join(
                f"{'Analyst' if m['role'] == 'user' else 'SENTINEL'}: {m['content'][:200]}"
                for m in recent_messages[-6:]
            )
            self._ensure_chain()
            with dspy.context(lm=lm):
                result = self._summarizer(
                    conversation=conversation,
                    previous_summary=old_summary or "No previous context.",
                )
            with get_db() as db:
                session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
                if session:
                    session.summary = result.summary
        except Exception as e:
            logger.warning("chat.update_summary_failed: %s", e)

    # ── Main Chat ─────────────────────────────────────────────────────────

    async def chat(
        self,
        question: str,
        session_id: Optional[str] = None,
        history: Optional[List[Dict]] = None,
        preferred_provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        # Per-request LM selection (honors dropdown choice)
        lm = get_lm(preferred=preferred_provider)
        provider_used = get_llm_provider().provider
        # Auto-create session if none provided
        if not session_id:
            result = self.create_session(title=question[:60])
            session_id = result["session_id"]

        # Get session context
        summary, recent_messages = self._get_session_context(session_id)

        # Save user message
        self._save_message(session_id, "user", question)

        # Retrieve context from all data sources
        context = self._retriever.retrieve(question, top_k=8)
        context_str = self._format_context(context)

        # Build conversation context
        if history and not recent_messages:
            conv_context = "\n".join(
                f"{'Analyst' if m['role'] == 'user' else 'SENTINEL'}: {m['content']}"
                for m in history[-6:]
            )
        elif recent_messages:
            conv_context = "\n".join(
                f"{'Analyst' if m['role'] == 'user' else 'SENTINEL'}: {m['content'][:200]}"
                for m in recent_messages[-6:]
            )
        else:
            conv_context = ""

        summary_context = summary or "First message in this session."
        if conv_context:
            summary_context = f"{summary_context}\n\nRecent exchanges:\n{conv_context}"

        # Generate answer
        try:
            self._ensure_chain()
            with dspy.context(lm=lm):
                result = self._chain(
                    question=question,
                    context=context_str,
                    conversation_summary=summary_context,
                )
            provider = get_llm_provider()

            # Build clickable references from retrieved docs
            references = self._extract_references(context)

            answer_data = {
                "session_id": session_id,
                "answer": result.answer,
                "confidence": result.confidence,
                "sources_used": [s.strip() for s in result.sources_used.split(",")],
                "llm_provider": provider.provider,
                "context_summary": {
                    "wazuh_alerts": len(context["wazuh_alerts"]),
                    "archives": len(context.get("archives", [])),
                    "monitoring": len(context.get("monitoring", [])),
                    "statistics": len(context.get("statistics", [])),
                    "incidents": len(context["incidents"]),
                    "correlated": len(context["correlated"]),
                    "suricata_alerts": len(context["suricata_alerts"]),
                },
                "references": references,
            }

            # Save assistant message
            self._save_message(
                session_id, "assistant", result.answer,
                confidence=result.confidence,
                sources_used=answer_data["sources_used"],
                context_summary={**answer_data["context_summary"], "references": references},
                llm_provider=provider.provider,
            )

            # Update rolling summary periodically
            recent_messages.append({"role": "user", "content": question})
            recent_messages.append({"role": "assistant", "content": result.answer})
            self._update_summary(session_id, recent_messages, summary)

            return answer_data

        except Exception as e:
            logger.error("chat_engine.failed: %s", e)
            error_msg = f"Error processing query: {str(e)}. Please try again."
            self._save_message(session_id, "assistant", error_msg)
            return {
                "session_id": session_id,
                "answer": error_msg,
                "confidence": "low",
                "sources_used": [],
                "error": str(e),
            }

    def _extract_references(self, context: Dict) -> list:
        """Extract clickable references from all retrieved documents."""
        refs = []
        seen = set()

        # Wazuh alerts
        for doc in context.get("wazuh_alerts", []):
            doc_id = doc.get("_doc_id", "")
            doc_index = doc.get("_doc_index", "")
            if not doc_id or doc_id in seen:
                continue
            seen.add(doc_id)
            refs.append({
                "id": doc_id,
                "index": doc_index,
                "source": "alerts",
                "label": doc.get("rule_description") or "Wazuh Alert",
                "timestamp": doc.get("timestamp", ""),
                "detail": f"Level {doc.get('rule_level', '?')} | Agent: {doc.get('agent_name', '?')} | IP: {doc.get('src_ip') or doc.get('agent_ip') or '?'}",
            })

        # Archives
        for doc in context.get("archives", []):
            doc_id = doc.get("_doc_id", "")
            doc_index = doc.get("_doc_index", "")
            if not doc_id or doc_id in seen:
                continue
            seen.add(doc_id)
            log_preview = (doc.get("full_log") or "")[:120]
            refs.append({
                "id": doc_id,
                "index": doc_index,
                "source": "archives",
                "label": doc.get("rule_description") or doc.get("location") or "Archive Event",
                "timestamp": doc.get("timestamp", ""),
                "detail": log_preview,
            })

        # Correlated incidents (from PostgreSQL — no OpenSearch ID)
        for doc in context.get("correlated", []):
            refs.append({
                "id": doc.get("id", ""),
                "index": "",
                "source": "correlated",
                "label": f"Correlated: {doc.get('wazuh_rule', '?')} + {doc.get('suricata_signature', '?')}",
                "timestamp": doc.get("created_at", ""),
                "detail": f"Severity: {doc.get('combined_severity', '?')} | MITRE: {doc.get('mitre_technique_id', '?')} | IP: {doc.get('shared_ip', '?')}",
            })

        return refs[:30]  # Cap at 30 references

    def _format_context(self, context: Dict) -> str:
        parts = []

        if context.get("stats"):
            parts.append(f"=== INCIDENT STATISTICS ===\n{json.dumps(context['stats'], indent=2, default=str)}")

        if context["wazuh_alerts"]:
            parts.append(
                f"=== RECENT WAZUH ALERTS ({len(context['wazuh_alerts'])}) ===\n"
                + json.dumps(context["wazuh_alerts"][:5], indent=2, default=str)
            )

        if context.get("archives"):
            parts.append(
                f"=== WAZUH ARCHIVES — ALL RAW EVENTS incl. pfSense syslog ({len(context['archives'])}) ===\n"
                + json.dumps(context["archives"][:5], indent=2, default=str)
            )

        if context.get("monitoring"):
            parts.append(
                f"=== WAZUH MONITORING — AGENT STATUS ({len(context['monitoring'])}) ===\n"
                + json.dumps(context["monitoring"][:5], indent=2, default=str)
            )

        if context.get("statistics"):
            parts.append(
                f"=== WAZUH STATISTICS — MANAGER METRICS ({len(context['statistics'])}) ===\n"
                + json.dumps(context["statistics"][:3], indent=2, default=str)
            )

        if context["incidents"]:
            parts.append(
                f"=== RECENT INCIDENTS ({len(context['incidents'])}) ===\n"
                + json.dumps(context["incidents"][:5], indent=2, default=str)
            )

        if context["correlated"]:
            parts.append(
                f"=== CORRELATED INCIDENTS ({len(context['correlated'])}) ===\n"
                + json.dumps(context["correlated"][:5], indent=2, default=str)
            )

        if context["suricata_alerts"]:
            parts.append(
                f"=== SURICATA IDS ALERTS ({len(context['suricata_alerts'])}) ===\n"
                + json.dumps(context["suricata_alerts"][:5], indent=2, default=str)
            )

        if context.get("agent_activity"):
            parts.append(
                f"=== AGENT ACTIVITY LOG ===\n"
                + json.dumps(context["agent_activity"][:5], indent=2, default=str)
            )

        return "\n\n".join(parts) if parts else "No relevant data found in any data source."
