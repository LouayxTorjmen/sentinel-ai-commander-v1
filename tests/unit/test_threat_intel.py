"""Unit tests for ThreatIntelAgent."""
import pytest
from unittest.mock import MagicMock, patch

@pytest.fixture
def mock_settings(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "test")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test")
    monkeypatch.setenv("REDIS_PASSWORD", "test")
    monkeypatch.setenv("MYSQL_PASSWORD", "test")
    monkeypatch.setenv("MYSQL_ROOT_PASSWORD", "test")

class TestThreatIntelAgent:

    def test_returns_intel_structure(self, mock_settings):
        with patch("ai_agents.integrations.redis_manager.get_redis") as mock_redis:
            mock_redis.return_value.get = MagicMock(return_value=None)
            mock_redis.return_value.set = MagicMock(return_value=True)
            from ai_agents.agents.threat_intel.threat_intel_agent import ThreatIntelAgent
            agent = ThreatIntelAgent()
            import asyncio
            result = asyncio.run(agent.run({
                "mitre_techniques": ["T1110", "T1078"],
                "iocs": {"ip_addresses": ["203.0.113.42"], "domains": [], "hashes": [], "usernames": []}
            }))
            assert "mitre" in result
            assert "ip_reputation" in result
            assert "nvd_cves" in result

    def test_redis_cache_hit(self, mock_settings):
        cached = {"technique_id": "T1110", "source": "cache"}
        with patch("ai_agents.integrations.redis_manager.get_redis") as mock_redis:
            mock_redis.return_value.get = MagicMock(return_value=cached)
            mock_redis.return_value.set = MagicMock(return_value=True)
            from ai_agents.agents.threat_intel.threat_intel_agent import ThreatIntelAgent
            agent = ThreatIntelAgent()
            import asyncio
            result = asyncio.run(agent.run({
                "mitre_techniques": ["T1110"],
                "iocs": {"ip_addresses": [], "domains": [], "hashes": [], "usernames": []}
            }))
            assert result["mitre"][0]["technique_id"] == "T1110"

    def test_empty_input_returns_empty_intel(self, mock_settings):
        with patch("ai_agents.integrations.redis_manager.get_redis") as mock_redis:
            mock_redis.return_value.get = MagicMock(return_value=None)
            mock_redis.return_value.set = MagicMock(return_value=True)
            from ai_agents.agents.threat_intel.threat_intel_agent import ThreatIntelAgent
            agent = ThreatIntelAgent()
            import asyncio
            result = asyncio.run(agent.run({"mitre_techniques": [], "iocs": {}}))
            assert result["mitre"] == []
            assert result["ip_reputation"] == []
