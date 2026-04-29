import { useState, useRef, useEffect } from "react";

const API_BASE = "";

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

function StatusDot({ status }) {
  const color = status === "ok" ? "#22c55e" : status === "error" ? "#ef4444" : "#eab308";
  return (
    <span
      style={{
        display: "inline-block",
        width: 8,
        height: 8,
        borderRadius: "50%",
        background: color,
        marginRight: 6,
      }}
    />
  );
}

function Message({ msg }) {
  const isUser = msg.role === "user";
  return (
    <div
      style={{
        display: "flex",
        justifyContent: isUser ? "flex-end" : "flex-start",
        marginBottom: 12,
      }}
    >
      <div
        style={{
          maxWidth: "80%",
          padding: "12px 16px",
          borderRadius: isUser ? "18px 18px 4px 18px" : "18px 18px 18px 4px",
          background: isUser ? "#1a3a5c" : "#1e293b",
          color: "#e2e8f0",
          fontSize: 14,
          lineHeight: 1.6,
          border: isUser ? "1px solid #2563eb" : "1px solid #334155",
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
        }}
      >
        {!isUser && msg.provider && (
          <div
            style={{
              fontSize: 10,
              color: "#64748b",
              marginBottom: 4,
              fontFamily: "monospace",
            }}
          >
            {msg.provider === "gemini" ? "✨ Gemini" : msg.provider === "groq" ? "☁️ Groq" : "🏠 Ollama"} •{" "}
            {msg.confidence || ""}
            {msg.sources && msg.sources.length > 0 && ` • Sources: ${msg.sources.join(", ")}`}
          </div>
        )}
        <div>{msg.content}</div>
        {msg.tool_calls && msg.tool_calls.length > 0 && (
          <ToolCallsBlock calls={msg.tool_calls} iterations={msg.iterations} />
        )}
        {msg.context_summary && (
          <div
            style={{
              marginTop: 8,
              padding: "6px 10px",
              background: "#0f172a",
              borderRadius: 8,
              fontSize: 11,
              color: "#94a3b8",
              fontFamily: "monospace",
            }}
          >
            📊 Context: {msg.context_summary.wazuh_alerts} Wazuh alerts •{" "}
            {msg.context_summary.incidents} incidents •{" "}
            {msg.context_summary.correlated} correlated •{" "}
            {msg.context_summary.suricata_alerts} Suricata
          </div>
        )}
      </div>
    </div>
  );
}

function ToolCallsBlock({ calls, iterations }) {
  const [openIdx, setOpenIdx] = React.useState(null);
  return (
    <div style={{ marginTop: 10, borderTop: "1px solid #1e293b", paddingTop: 8 }}>
      <div style={{ fontSize: 11, color: "#64748b", marginBottom: 6, fontWeight: 600 }}>
        SOURCES — {calls.length} tool call{calls.length === 1 ? "" : "s"}
        {iterations ? ` (${iterations} iteration${iterations === 1 ? "" : "s"})` : ""}
      </div>
      {calls.map((c, i) => {
        const isOpen = openIdx === i;
        return (
          <div
            key={i}
            style={{
              marginBottom: 6,
              background: "#0f172a",
              border: "1px solid #1e293b",
              borderRadius: 6,
              overflow: "hidden",
            }}
          >
            <div
              style={{
                padding: "6px 10px",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: 8,
                fontSize: 11,
                fontFamily: "monospace",
                color: "#cbd5e1",
              }}
              onClick={() => setOpenIdx(isOpen ? null : i)}
            >
              <span style={{ color: "#06b6d4" }}>{isOpen ? "▼" : "▶"}</span>
              <span style={{ color: "#10b981", fontWeight: 600 }}>{c.name}</span>
              <span style={{ color: "#64748b" }}>
                ({Object.entries(c.args || {}).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ")})
              </span>
              <span style={{ marginLeft: "auto", color: "#94a3b8" }}>{c.result_summary}</span>
            </div>
            {isOpen && (
              <div
                style={{
                  borderTop: "1px solid #1e293b",
                  padding: "8px 10px",
                  fontFamily: "monospace",
                  fontSize: 10.5,
                  color: "#cbd5e1",
                  maxHeight: 320,
                  overflow: "auto",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {c.result ? JSON.stringify(c.result, null, 2) : "(no result data)"}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function SidePanel({ health, stats }) {
  return (
    <div
      style={{
        width: 260,
        background: "#0f172a",
        borderRight: "1px solid #1e293b",
        padding: 16,
        overflowY: "auto",
        fontSize: 13,
        color: "#94a3b8",
        flexShrink: 0,
      }}
    >
      <div style={{ fontSize: 18, fontWeight: 700, color: "#f1f5f9", marginBottom: 20 }}>
        🛡️ SENTINEL-AI
      </div>
      <div style={{ fontSize: 11, color: "#64748b", marginBottom: 16 }}>
        Commander v2.0 — RAG Chat
      </div>

      <div style={{ marginBottom: 16 }}>
        <div style={{ fontWeight: 600, color: "#cbd5e1", marginBottom: 8 }}>System Health</div>
        {health ? (
          <>
            <div><StatusDot status={health.redis ? "ok" : "error"} />Redis</div>
            <div><StatusDot status={health.llm?.groq_available ? "ok" : "error"} />Groq</div>
            <div><StatusDot status={health.llm?.gemini_available ? "ok" : "error"} />Gemini</div>
            <div><StatusDot status={health.llm?.ollama_available ? "ok" : "warn"} />Ollama (fallback)</div>
            <div><StatusDot status={health.ml?.anomaly_detector?.is_fitted ? "ok" : "warn"} />ML Models</div>
          </> 
        ) : (
          <div style={{ color: "#475569" }}>Loading...</div>
        )}
      </div>

      {stats && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontWeight: 600, color: "#cbd5e1", marginBottom: 8 }}>Incidents</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: "#f1f5f9" }}>
            {stats.total_incidents}
          </div>
          <div style={{ display: "flex", gap: 6, marginTop: 6, flexWrap: "wrap" }}>
            {Object.entries(stats.by_severity || {}).map(([sev, count]) => (
              <span
                key={sev}
                style={{
                  padding: "2px 8px",
                  borderRadius: 10,
                  fontSize: 11,
                  fontWeight: 600,
                  background: SEVERITY_COLORS[sev] + "20",
                  color: SEVERITY_COLORS[sev],
                }}
              >
                {sev}: {count}
              </span>
            ))}
          </div>
        </div>
      )}

      <div style={{ marginTop: 20, borderTop: "1px solid #1e293b", paddingTop: 12 }}>
        <div style={{ fontWeight: 600, color: "#cbd5e1", marginBottom: 8 }}>Quick Actions</div>
        {[
          "Show recent critical incidents",
          "Any brute force attacks today?",
          "Which IPs triggered the most alerts?",
          "Correlate Wazuh and Suricata alerts",
          "What MITRE techniques were detected?",
          "Show ML anomaly detection status",
        ].map((q) => (
           
            <button
            key={q}
            onClick={() => {
              const event = new CustomEvent("quickAction", { detail: q });
              window.dispatchEvent(event);
            }}
            style={{
              display: "block",
              width: "100%",
              padding: "6px 10px",
              marginBottom: 4,
              background: "transparent",
              border: "1px solid #1e293b",
              borderRadius: 6,
              color: "#94a3b8",
              fontSize: 12,
              cursor: "pointer",
              textAlign: "left",
              transition: "all 0.15s",
            }}
            onMouseOver={(e) => {
              e.target.style.background = "#1e293b";
              e.target.style.color = "#e2e8f0";
            }}
            onMouseOut={(e) => {
              e.target.style.background = "transparent";
              e.target.style.color = "#94a3b8";
            }}
          >
            {q}
          </button>
        ))}
      </div>
    </div>
  );
}

export default function SentinelChat() {
  const [sessionId, setSessionId] = useState(localStorage.getItem("sentinel_react_session") || null);

  useEffect(() => {
    const loadHistory = async () => {
      try {
        const res = await fetch("/api/chat/sessions");
        const sessionsData = await res.json();
        if (sessionsData && sessionsData.length > 0) {
          let activeId = localStorage.getItem("sentinel_react_session");
          if (!activeId || !sessionsData.find(s => s.session_id === activeId)) {
            activeId = sessionsData[0].session_id;
          }
          setSessionId(activeId);
          localStorage.setItem("sentinel_react_session", activeId);
          const msgRes = await fetch(`/api/chat/sessions/${activeId}`);
          const msgs = await msgRes.json();
          if (msgs && msgs.length > 0) { setMessages(msgs); }
        }
      } catch (err) { console.error("Failed to load history", err); }
    };
    loadHistory();
  }, []);

  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content:
        "Welcome to SENTINEL-AI Commander. I have access to your Wazuh HIDS alerts, Suricata NIDS data, incident database, and correlated threat intelligence. Ask me anything about your security posture.",
    },
  ]);
  const [input, setInput] = useState(""); const [provider, setProvider] = useState("gemini");
const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const chatEndRef = useRef(null);

  useEffect(() => {
    fetch("/api/health").then(r => r.json()).then(setHealth).catch(() => {});
    fetch("/api/stats").then(r => r.json()).then(setStats).catch(() => {});
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    const handler = (e) => {
      setInput(e.detail);
      handleSend(e.detail);
    };
    window.addEventListener("quickAction", handler);
    return () => window.removeEventListener("quickAction", handler);
  }, [messages]);

  const handleSend = async (overrideMsg) => {
    const msg = overrideMsg || input;
    if (!msg.trim() || loading) return;

    const userMsg = { role: "user", content: msg };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setLoading(true);

    try {
      const history = newMessages
        .filter((m) => m.role !== "system")
        .map((m) => ({ role: m.role, content: m.content }));

      const resp = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: msg,
          history,
          preferred_provider: provider,
          session_id: sessionId
        }),
      });

      const data = await resp.json();
      if (data.session_id && data.session_id !== sessionId) { setSessionId(data.session_id); localStorage.setItem('sentinel_react_session', data.session_id); }

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.answer || data.detail || "No response received.",
          provider: data.llm_provider,
          confidence: data.confidence,
          sources: data.sources_used,
          context_summary: data.context_summary,
          tool_calls: data.agentic?.tool_calls || [],
          iterations: data.agentic?.iterations,
        },
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `Connection error: ${err.message}. Ensure the AI agents container is running.`,
        },
      ]);
    }
    setLoading(false);
  };

  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        width: "100%",
        background: "#0f172a",
        fontFamily:
          "'JetBrains Mono', 'Fira Code', 'SF Mono', 'Cascadia Code', monospace",
        color: "#e2e8f0",
      }}
    >
      <SidePanel health={health} stats={stats} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        {/* Header */}
        <div
          style={{
            padding: "12px 20px",
            borderBottom: "1px solid #1e293b",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            background: "#0f172a",
          }}
        >
          <div>
            <span style={{ fontSize: 15, fontWeight: 600 }}>Security Operations Chat</span>
            <span style={{ fontSize: 12, color: "#64748b", marginLeft: 12 }}>
              RAG-powered • Cloud LLM (Gemini/Groq) + Ollama fallback
            </span>
          </div>
          {health && (
            <div style={{ fontSize: 11, color: "#64748b" }}>
              LLM: {health.llm?.current_provider || "unknown"} •{" "}
              ML: {health.ml?.anomaly_detector?.is_fitted ? "trained" : "untrained"}
            </div>
          )}
        </div>

        {/* Messages */}
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 20px" }}>
          {messages.map((msg, i) => (
            <Message key={i} msg={msg} />
          ))}
          {loading && (
            <div style={{ display: "flex", justifyContent: "flex-start", marginBottom: 12 }}>
              <div
                style={{
                  padding: "12px 16px",
                  borderRadius: "18px 18px 18px 4px",
                  background: "#1e293b",
                  border: "1px solid #334155",
                  color: "#94a3b8",
                  fontSize: 14,
                }}
              >
                <span className="loading-dots">Querying data sources</span>
                <style>{`
                  .loading-dots::after {
                    content: '';
                    animation: dots 1.5s steps(4, end) infinite;
                  }
                  @keyframes dots {
                    0% { content: ''; }
                    25% { content: '.'; }
                    50% { content: '..'; }
                    75% { content: '...'; }
                  }
                `}</style>
              </div>
            </div>
          )}
          <div ref={chatEndRef} />
        </div>

        {/* Input */}
        <div
          style={{
            padding: "12px 20px",
            borderTop: "1px solid #1e293b",
            background: "#0f172a",
          }}
        >
          <div style={{ display: "flex", gap: 8 }}>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSend()}

            />

            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              style={{
                padding: "8px",
                borderRadius: 10,
                border: "1px solid #334155",
                background: "#1e293b",
                color: "#fff",
                fontSize: 12,
                marginRight: 8
              }}
            >
              <option value="gemini">Gemini</option>
              <option value="groq">Groq</option>
              <option value="ollama">Ollama (local)</option>
            </select>

            <input
              placeholder="Ask about alerts, incidents, MITRE techniques, or security posture..."
              style={{
                flex: 1,
                padding: "10px 14px",
                borderRadius: 10,
                border: "1px solid #334155",
                background: "#1e293b",
                color: "#e2e8f0",
                fontSize: 14,
                outline: "none",
                fontFamily: "inherit",
              }}
            />
            <select 
            <button
              onClick={() => handleSend()}
              disabled={loading || !input.trim()}
              style={{
                padding: "10px 20px",
                borderRadius: 10,
                border: "none",
                background: loading ? "#334155" : "#2563eb",
                color: "#fff",
                fontSize: 14,
                fontWeight: 600,
                cursor: loading ? "not-allowed" : "pointer",
                fontFamily: "inherit",
                transition: "background 0.15s",
              }}
            >
              Send
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
