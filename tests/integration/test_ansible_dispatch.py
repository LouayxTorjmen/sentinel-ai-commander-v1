"""Integration tests for AnsibleDispatchAgent."""
import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock

@pytest.fixture
def mock_env(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "test")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test")
    monkeypatch.setenv("REDIS_PASSWORD", "test")
    monkeypatch.setenv("MYSQL_PASSWORD", "test")
    monkeypatch.setenv("MYSQL_ROOT_PASSWORD", "test")
    monkeypatch.setenv("ANSIBLE_CONFIDENCE_THRESHOLD", "0.85")

class TestAnsibleDispatchAgent:

    def test_no_dispatch_below_threshold(self, mock_env):
        with patch("dspy.LM"), patch("dspy.configure"):
            from ai_agents.agents.ansible_dispatch.ansible_dispatch_agent import AnsibleDispatchAgent
            agent = AnsibleDispatchAgent()
            mock_decision = MagicMock()
            mock_decision.should_respond = "yes"
            mock_decision.playbook = "brute_force_response"
            mock_decision.extra_vars = "{}"
            mock_decision.reasoning = "High confidence brute force"
            agent._decide = MagicMock(return_value=mock_decision)
            result = asyncio.run(agent.run({
                "analysis": "Brute force attack detected",
                "alert_type": "brute_force",
                "severity": "high",
                "confidence": 0.50,
                "source_ip": "203.0.113.42",
                "incident_id": "test-001"
            }))
            assert result["executed"] is False

    def test_dispatch_above_threshold(self, mock_env):
        with patch("dspy.LM"), patch("dspy.configure"):
            from ai_agents.agents.ansible_dispatch.ansible_dispatch_agent import AnsibleDispatchAgent
            agent = AnsibleDispatchAgent()
            mock_decision = MagicMock()
            mock_decision.should_respond = "yes"
            mock_decision.playbook = "brute_force_response"
            mock_decision.extra_vars = '{"block_duration": 3600}'
            mock_decision.reasoning = "High confidence brute force"
            agent._decide = MagicMock(return_value=mock_decision)
            agent._trigger = MagicMock()
            agent._trigger.run_playbook = AsyncMock(return_value={"status": "successful", "rc": 0})
            result = asyncio.run(agent.run({
                "analysis": "Brute force attack detected",
                "alert_type": "brute_force",
                "severity": "high",
                "confidence": 0.95,
                "source_ip": "203.0.113.42",
                "incident_id": "test-002"
            }))
            assert result["executed"] is True
            assert result["playbook"] == "brute_force_response"

    def test_no_dispatch_when_decision_is_no(self, mock_env):
        with patch("dspy.LM"), patch("dspy.configure"):
            from ai_agents.agents.ansible_dispatch.ansible_dispatch_agent import AnsibleDispatchAgent
            agent = AnsibleDispatchAgent()
            mock_decision = MagicMock()
            mock_decision.should_respond = "no"
            mock_decision.playbook = "none"
            mock_decision.extra_vars = "{}"
            mock_decision.reasoning = "Low severity, no action needed"
            agent._decide = MagicMock(return_value=mock_decision)
            result = asyncio.run(agent.run({
                "analysis": "Minor anomaly",
                "alert_type": "other",
                "severity": "low",
                "confidence": 0.90,
                "source_ip": "",
                "incident_id": "test-003"
            }))
            assert result["executed"] is False
