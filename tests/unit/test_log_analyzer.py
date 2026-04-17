"""Unit tests for LogAnalyzerAgent. Uses mocked DSPy LM to avoid real API calls."""
import json
import pytest
from unittest.mock import MagicMock, patch

SAMPLE_ALERT = {
    "id": "1701234567.123456",
    "rule": {"id": 100010, "level": 10, "description": "SSH brute force attack", "mitre": {"technique": ["T1110"]}},
    "data": {"srcip": "203.0.113.42", "dstip": "172.25.0.50"},
    "full_log": "Failed password for root from 203.0.113.42"
}

@pytest.fixture
def mock_settings(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "test")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test")
    monkeypatch.setenv("REDIS_PASSWORD", "test")
    monkeypatch.setenv("MYSQL_PASSWORD", "test")
    monkeypatch.setenv("MYSQL_ROOT_PASSWORD", "test")

def make_mock_classification():
    m = MagicMock()
    m.alert_type = "brute_force"
    m.severity = "high"
    m.mitre_techniques = "T1110,T1110.001"
    m.confidence = "0.92"
    m.summary = "SSH brute force attack from 203.0.113.42"
    return m

def make_mock_iocs():
    m = MagicMock()
    m.ip_addresses = "203.0.113.42"
    m.domains = ""
    m.hashes = ""
    m.usernames = "root"
    return m

class TestLogAnalyzerAgent:

    def test_classification_output_structure(self, mock_settings):
        with patch("dspy.LM"), patch("dspy.configure"):
            from ai_agents.agents.log_analyzer.log_analyzer import LogAnalyzerAgent
            agent = LogAnalyzerAgent()
            agent._classify = MagicMock(return_value=make_mock_classification())
            agent._extract_iocs = MagicMock(return_value=make_mock_iocs())
            import asyncio
            result = asyncio.run(agent.run({"alert": SAMPLE_ALERT}))
            assert result["alert_type"] == "brute_force"
            assert result["severity"] == "high"
            assert "T1110" in result["mitre_techniques"]
            assert result["confidence"] == 0.92
            assert "203.0.113.42" in result["iocs"]["ip_addresses"]

    def test_mitre_techniques_parsed_as_list(self, mock_settings):
        with patch("dspy.LM"), patch("dspy.configure"):
            from ai_agents.agents.log_analyzer.log_analyzer import LogAnalyzerAgent
            agent = LogAnalyzerAgent()
            classification = make_mock_classification()
            classification.mitre_techniques = "T1110, T1110.001, T1078"
            agent._classify = MagicMock(return_value=classification)
            agent._extract_iocs = MagicMock(return_value=make_mock_iocs())
            import asyncio
            result = asyncio.run(agent.run({"alert": SAMPLE_ALERT}))
            assert isinstance(result["mitre_techniques"], list)
            assert len(result["mitre_techniques"]) == 3

    def test_empty_iocs_handled(self, mock_settings):
        with patch("dspy.LM"), patch("dspy.configure"):
            from ai_agents.agents.log_analyzer.log_analyzer import LogAnalyzerAgent
            agent = LogAnalyzerAgent()
            agent._classify = MagicMock(return_value=make_mock_classification())
            empty_iocs = MagicMock()
            empty_iocs.ip_addresses = ""
            empty_iocs.domains = ""
            empty_iocs.hashes = ""
            empty_iocs.usernames = ""
            agent._extract_iocs = MagicMock(return_value=empty_iocs)
            import asyncio
            result = asyncio.run(agent.run({"alert": SAMPLE_ALERT}))
            assert result["iocs"]["ip_addresses"] == []
            assert result["iocs"]["domains"] == []
