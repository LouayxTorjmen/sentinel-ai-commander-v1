"""
Feature extraction from heterogeneous security events.

Converts raw Wazuh alerts and Suricata events into numerical
feature vectors suitable for ML models.

PhD Contribution: Novel feature engineering for cross-source
security telemetry combining host (HIDS) and network (NIDS) signals.
"""
import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

# MITRE tactic → numeric encoding
TACTIC_MAP = {
    "reconnaissance": 0, "resource-development": 1, "initial-access": 2,
    "execution": 3, "persistence": 4, "privilege-escalation": 5,
    "defense-evasion": 6, "credential-access": 7, "discovery": 8,
    "lateral-movement": 9, "collection": 10, "command-and-control": 11,
    "exfiltration": 12, "impact": 13, "unknown": 14,
}

ALERT_TYPE_MAP = {
    "brute_force": 0, "malware": 1, "lateral_movement": 2,
    "exfiltration": 3, "recon": 4, "privilege_escalation": 5,
    "c2": 6, "web_attack": 7, "policy_violation": 8, "other": 9,
}


class FeatureExtractor:
    """Extract ML features from security events."""

    def extract_wazuh_features(self, alert: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from a Wazuh alert.

        Features (12-dimensional):
          0: rule_level (1-15, normalized)
          1: hour_of_day (0-23, normalized)
          2: day_of_week (0-6, normalized)
          3: src_ip_hash (0-1, hashed)
          4: agent_ip_hash (0-1, hashed)
          5: mitre_tactic_encoded (0-14, normalized)
          6: has_mitre (0 or 1)
          7: rule_id_bucket (hash mod 100, normalized)
          8: is_fim_alert (0 or 1)
          9: is_vuln_alert (0 or 1)
          10: data_field_count (normalized)
          11: description_length (normalized)
        """
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        data = alert.get("data", {})
        timestamp = alert.get("timestamp", "")

        # Parse timestamp
        hour, dow = 12, 3  # defaults
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            hour = dt.hour
            dow = dt.weekday()
        except (ValueError, AttributeError):
            pass

        # MITRE tactic
        mitre_ids = rule.get("mitre", {}).get("id", [])
        has_mitre = 1 if mitre_ids else 0
        tactic = rule.get("mitre", {}).get("tactic", ["unknown"])
        tactic_enc = TACTIC_MAP.get(
            (tactic[0] if tactic else "unknown").lower().replace(" ", "-"), 14
        )

        # IP hashing
        src_ip = data.get("srcip", "")
        agent_ip = agent.get("ip", "")

        features = np.array([
            rule.get("level", 5) / 15.0,
            hour / 23.0,
            dow / 6.0,
            self._ip_hash(src_ip),
            self._ip_hash(agent_ip),
            tactic_enc / 14.0,
            has_mitre,
            (hash(str(rule.get("id", 0))) % 100) / 100.0,
            1 if rule.get("groups", []) and "syscheck" in rule.get("groups", []) else 0,
            1 if "vulnerability" in rule.get("description", "").lower() else 0,
            min(len(data), 20) / 20.0,
            min(len(rule.get("description", "")), 200) / 200.0,
        ], dtype=np.float32)

        return features

    def extract_suricata_features(self, event: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from a Suricata event.

        Features (12-dimensional, aligned with Wazuh for fusion):
          0: severity (1-4, normalized, inverted so 1=highest)
          1: hour_of_day
          2: day_of_week
          3: src_ip_hash
          4: dest_ip_hash
          5: dest_port_bucket
          6: is_inbound (0/1)
          7: protocol_encoded
          8: signature_id_bucket
          9: has_mitre_metadata
          10: src_port_ephemeral (0/1)
          11: category_hash
        """
        alert = event.get("alert", {})
        timestamp = event.get("timestamp", "")

        hour, dow = 12, 3
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            hour = dt.hour
            dow = dt.weekday()
        except (ValueError, AttributeError):
            pass

        src_port = event.get("src_port", 0)
        dest_port = event.get("dest_port", 0)
        proto = event.get("proto", "TCP").upper()
        proto_map = {"TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3}

        features = np.array([
            (5 - alert.get("severity", 3)) / 4.0,  # invert: sev 1 → 1.0
            hour / 23.0,
            dow / 6.0,
            self._ip_hash(event.get("src_ip", "")),
            self._ip_hash(event.get("dest_ip", "")),
            min(dest_port, 65535) / 65535.0,
            1 if dest_port < 1024 else 0,  # common service port = inbound
            proto_map.get(proto, 3) / 3.0,
            (alert.get("signature_id", 0) % 1000) / 1000.0,
            1 if alert.get("metadata", {}).get("mitre_attack") else 0,
            1 if src_port > 49152 else 0,  # ephemeral
            self._str_hash(alert.get("category", "")) / 1.0,
        ], dtype=np.float32)

        return features

    def extract_combined_features(
        self, wazuh_alert: Dict, suricata_event: Dict
    ) -> np.ndarray:
        """Fuse Wazuh and Suricata features into a 24-dim combined vector."""
        wf = self.extract_wazuh_features(wazuh_alert)
        sf = self.extract_suricata_features(suricata_event)
        return np.concatenate([wf, sf])

    @staticmethod
    def _ip_hash(ip: str) -> float:
        if not ip:
            return 0.0
        h = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        return (h % 10000) / 10000.0

    @staticmethod
    def _str_hash(s: str) -> float:
        if not s:
            return 0.0
        h = int(hashlib.md5(s.encode()).hexdigest()[:8], 16)
        return (h % 10000) / 10000.0
