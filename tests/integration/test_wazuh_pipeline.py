"""Integration tests for the full alert processing pipeline."""
import json
import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures"

@pytest.fixture
def sample_alert():
    with open(FIXTURE_DIR / "sample_wazuh_alert.json") as f:
        return json.load(f)

@pytest.fixture
def mock_env(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "test")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test")
    monkeypatch.setenv("REDIS_PASSWORD", "test")
    monkeypatch.setenv("MYSQL_PASSWORD", "test")
    monkeypatch.setenv("MYSQL_ROOT_PASSWORD", "test")

class TestWazuhAlertPipeline:

    def test_fixture_loads_correctly(self, sample_alert):
        assert "rule" in sample_alert
        assert "data" in sample_alert
        assert sample_alert["data"]["srcip"] == "203.0.113.42"
        assert sample_alert["rule"]["level"] == 10

    def test_log_analyzer_processes_fixture(self, sample_alert, mock_env):
        with patch("dspy.LM"), patch("dspy.configure"):
            from ai_agents.agents.log_analyzer.log_analyzer import LogAnalyzerAgent
            agent = LogAnalyzerAgent()
            mock_cls = MagicMock()
            mock_cls.alert_type = "brute_force"
            mock_cls.severity = "high"
            mock_cls.mitre_techniques = "T1110,T1110.001"
            mock_cls.confidence = "0.95"
            mock_cls.summary = "SSH brute force from 203.0.113.42"
            mock_ioc = MagicMock()
            mock_ioc.ip_addresses = "203.0.113.42"
            mock_ioc.domains = ""
            mock_ioc.hashes = ""
            mock_ioc.usernames = "root"
            agent._classify = MagicMock(return_value=mock_cls)
            agent._extract_iocs = MagicMock(return_value=mock_ioc)
            result = asyncio.run(agent.run({"alert": sample_alert}))
            assert result["alert_type"] == "brute_force"
            assert result["severity"] == "high"
            assert result["confidence"] == 0.95
            assert "203.0.113.42" in result["iocs"]["ip_addresses"]

    def test_suricata_fixture_structure(self):
        with open(FIXTURE_DIR / "sample_suricata_eve.json") as f:
            eve = json.load(f)
        assert eve["event_type"] == "alert"
        assert "alert" in eve
        assert eve["alert"]["severity"] == 1
        assert eve["src_ip"] == "203.0.113.42"

    def test_nvd_fixture_structure(self):
        with open(FIXTURE_DIR / "sample_nvd_cve.json") as f:
            nvd = json.load(f)
        assert "vulnerabilities" in nvd
        cve = nvd["vulnerabilities"][0]["cve"]
        assert cve["id"] == "CVE-2023-38408"
        score = nvd["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
        assert score == 9.8
