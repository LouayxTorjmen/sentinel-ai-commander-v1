from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON, Enum
from sqlalchemy.orm import declarative_base
from datetime import datetime
import enum

Base = declarative_base()

class SeverityLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    ANALYZING = "analyzing"
    RESPONDING = "responding"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True)
    wazuh_alert_id = Column(String(128), index=True, nullable=True)
    rule_id = Column(Integer, nullable=True)
    rule_description = Column(Text, nullable=True)
    severity = Column(String(16), default=SeverityLevel.MEDIUM)
    status = Column(String(16), default=IncidentStatus.OPEN)
    source_ip = Column(String(45), nullable=True, index=True)
    dest_ip = Column(String(45), nullable=True)
    mitre_techniques = Column(JSON, default=list)
    alert_data = Column(JSON, default=dict)
    analysis = Column(Text, nullable=True)
    recommended_action = Column(String(256), nullable=True)
    confidence_score = Column(Float, default=0.0)
    playbook_executed = Column(String(128), nullable=True)
    playbook_result = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(String(36), primary_key=True)
    ioc_type = Column(String(32), index=True)
    ioc_value = Column(String(512), index=True)
    threat_data = Column(JSON, default=dict)
    source = Column(String(64))
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

class CVERecord(Base):
    __tablename__ = "cve_records"

    cve_id = Column(String(32), primary_key=True)
    description = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(256), nullable=True)
    severity = Column(String(16), nullable=True)
    affected_products = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    published_date = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)
    cached_at = Column(DateTime, default=datetime.utcnow)

class AgentActivity(Base):
    __tablename__ = "agent_activity"

    id = Column(String(36), primary_key=True)
    agent_name = Column(String(64), index=True)
    incident_id = Column(String(36), nullable=True, index=True)
    action = Column(String(128))
    input_data = Column(JSON, default=dict)
    output_data = Column(JSON, default=dict)
    duration_ms = Column(Integer, nullable=True)
    success = Column(Integer, default=1)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class CorrelatedIncident(Base):
    """
    Persists output from WazuhSuricataAgent._correlate().
    Cross-source (Wazuh HIDS + Suricata NIDS) incident with MITRE mapping.
    PhD core contribution: host+network telemetry fusion.
    """
    __tablename__ = "correlated_incidents"

    id = Column(String(64), primary_key=True)                    # CORR-<epoch>-<n>
    wazuh_alert_id = Column(String(128), nullable=True, index=True)
    wazuh_rule = Column(Text, nullable=True)
    wazuh_level = Column(Integer, nullable=True)
    suricata_signature = Column(Text, nullable=True)
    suricata_severity = Column(Integer, nullable=True)
    shared_ip = Column(String(45), nullable=True, index=True)
    combined_severity = Column(String(16), nullable=True)
    mitre_tactic = Column(String(128), nullable=True)
    mitre_technique_id = Column(String(32), nullable=True, index=True)
    mitre_technique_name = Column(String(256), nullable=True)
    attack_narrative = Column(Text, nullable=True)
    recommended_response = Column(Text, nullable=True)
    ansible_playbook = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class DiscoveredHost(Base):
    """
    Tracks hosts discovered by the auto-discovery network scanner.
    New hosts are automatically enrolled as Wazuh agents.
    """
    __tablename__ = "discovered_hosts"

    ip = Column(String(45), primary_key=True)
    hostname = Column(String(256), nullable=True)
    open_ports = Column(JSON, default=list)
    services = Column(JSON, default=list)
    os_guess = Column(String(32), nullable=True)          # linux, windows, freebsd
    role = Column(String(32), nullable=True)               # server, firewall, network_device
    wazuh_status = Column(String(32), default="unmonitored")  # unmonitored, enrolled, active, disconnected
    wazuh_agent_id = Column(String(8), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)


class ChatSession(Base):
    """Persistent chat sessions with conversation history."""
    __tablename__ = "chat_sessions"

    id = Column(String(36), primary_key=True)
    title = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    message_count = Column(Integer, default=0)
    summary = Column(Text, nullable=True)  # rolling context summary


class ChatMessage(Base):
    """Individual messages within a chat session."""
    __tablename__ = "chat_messages"

    id = Column(String(36), primary_key=True)
    session_id = Column(String(36), index=True)
    role = Column(String(16))  # user, assistant
    content = Column(Text)
    confidence = Column(String(16), nullable=True)
    sources_used = Column(JSON, default=list)
    context_summary = Column(JSON, default=dict)
    llm_provider = Column(String(32), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
