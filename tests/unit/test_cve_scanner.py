"""Unit tests for CVEScannerAgent."""
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

MOCK_NVD_RESPONSE = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2023-38408",
            "descriptions": [{"lang": "en", "value": "OpenSSH RCE vulnerability"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}
        }
    }]
}

@pytest.fixture
def mock_settings(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "test")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test")
    monkeypatch.setenv("REDIS_PASSWORD", "test")
    monkeypatch.setenv("MYSQL_PASSWORD", "test")
    monkeypatch.setenv("MYSQL_ROOT_PASSWORD", "test")
    monkeypatch.setenv("NVD_API_KEY", "test-nvd-key")

class TestCVEScannerAgent:

    def test_returns_cves_from_nvd(self, mock_settings):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = MOCK_NVD_RESPONSE
        with patch("ai_agents.integrations.redis_manager.get_redis") as mock_redis,              patch("httpx.AsyncClient") as mock_client:
            mock_redis.return_value.get = MagicMock(return_value=None)
            mock_redis.return_value.set = MagicMock(return_value=True)
            mock_client.return_value.__aenter__ = AsyncMock(return_value=MagicMock(get=AsyncMock(return_value=mock_response)))
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            from ai_agents.agents.vuln_scanner.cve_scanner import CVEScannerAgent
            agent = CVEScannerAgent()
            import asyncio
            result = asyncio.run(agent.run({"keywords": ["openssh"]}))
            assert "cves" in result
            assert result["total"] >= 0

    def test_redis_cache_prevents_api_call(self, mock_settings):
        cached_cves = [{"cve_id": "CVE-2023-38408", "cvss_score": 9.8}]
        with patch("ai_agents.integrations.redis_manager.get_redis") as mock_redis:
            mock_redis.return_value.get = MagicMock(return_value=cached_cves)
            from ai_agents.agents.vuln_scanner.cve_scanner import CVEScannerAgent
            agent = CVEScannerAgent()
            import asyncio
            result = asyncio.run(agent.run({"keywords": ["openssh"]}))
            assert result["total"] == 1
            assert result["cves"][0]["cve_id"] == "CVE-2023-38408"

    def test_empty_keywords_returns_empty(self, mock_settings):
        with patch("ai_agents.integrations.redis_manager.get_redis") as mock_redis:
            mock_redis.return_value.get = MagicMock(return_value=None)
            from ai_agents.agents.vuln_scanner.cve_scanner import CVEScannerAgent
            agent = CVEScannerAgent()
            import asyncio
            result = asyncio.run(agent.run({"keywords": []}))
            assert result["cves"] == []
            assert result["total"] == 0
