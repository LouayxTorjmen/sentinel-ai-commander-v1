import dspy

class AlertClassification(dspy.Signature):
    """Classify a security alert, extract MITRE ATT&CK techniques, and assess severity."""
    alert_json: str = dspy.InputField(desc="Raw Wazuh alert in JSON format")
    alert_type: str = dspy.OutputField(desc="Alert type: brute_force | malware | lateral_movement | exfiltration | recon | privilege_escalation | c2 | other")
    severity: str = dspy.OutputField(desc="Severity: low | medium | high | critical")
    mitre_techniques: str = dspy.OutputField(desc="Comma-separated MITRE ATT&CK technique IDs, e.g. T1110,T1078")
    confidence: str = dspy.OutputField(desc="Confidence score 0.0-1.0")
    summary: str = dspy.OutputField(desc="One-sentence human-readable summary of the threat")

class ThreatAnalysis(dspy.Signature):
    """Perform deep threat analysis combining alert data with threat intelligence."""
    alert_summary: str = dspy.InputField(desc="Classified alert summary")
    threat_intel: str = dspy.InputField(desc="Threat intelligence context (CVEs, IOCs, MITRE)")
    analysis: str = dspy.OutputField(desc="Detailed threat analysis paragraph")
    attack_chain: str = dspy.OutputField(desc="Likely attack chain steps")
    risk_score: str = dspy.OutputField(desc="Risk score 0-100")

class ResponseDecision(dspy.Signature):
    """Decide whether to trigger an automated Ansible playbook response."""
    threat_analysis: str = dspy.InputField(desc="Threat analysis result")
    alert_type: str = dspy.InputField(desc="Classified alert type")
    severity: str = dspy.InputField(desc="Alert severity")
    confidence: str = dspy.InputField(desc="Classification confidence")
    should_respond: str = dspy.OutputField(desc="yes | no")
    playbook: str = dspy.OutputField(desc="Playbook name: brute_force_response | malware_containment | lateral_movement_response | vulnerability_patch | incident_response | none")
    extra_vars: str = dspy.OutputField(desc="JSON string of Ansible extra_vars for the playbook")
    reasoning: str = dspy.OutputField(desc="One sentence explaining the decision")

class IOCExtraction(dspy.Signature):
    """Extract Indicators of Compromise from a security alert."""
    alert_json: str = dspy.InputField(desc="Raw alert JSON")
    ip_addresses: str = dspy.OutputField(desc="Comma-separated suspicious IP addresses")
    domains: str = dspy.OutputField(desc="Comma-separated suspicious domains")
    hashes: str = dspy.OutputField(desc="Comma-separated file hashes")
    usernames: str = dspy.OutputField(desc="Comma-separated suspicious usernames")


# ─── SECOPS-AI WAZUH/SURICATA CORRELATION SIGNATURES ─────────────────────────
# Merged from secops-ai project. Three DSPy signatures for:
#   1. Wazuh HIDS alert triage
#   2. Suricata NIDS alert enrichment
#   3. Cross-source HIDS+NIDS correlation (PhD core contribution)
# These can be compiled with dspy.MIPROv2 for 15-30% accuracy improvement.

class WazuhAlertTriageSignature(dspy.Signature):
    """
    Triage a single Wazuh Manager alert to determine its real-world severity,
    MITRE ATT&CK relevance, and any associated CVE references.

    The alert JSON comes from the Wazuh Manager REST API /alerts endpoint.
    It includes: rule.id, rule.level (1-15), rule.description, rule.mitre,
    agent.name, agent.ip, data (raw log fields), timestamp.

    Key Wazuh rule levels:
      1-3   Informational
      4-6   Low risk
      7-9   Medium risk (triggers this agent)
      10-12 High risk
      13-15 Critical — requires immediate response
    """

    # ── Inputs ────────────────────────────────────────────────────────────────
    wazuh_alert_json: str = dspy.InputField(
        desc="Full Wazuh alert in JSON format including rule, agent, and data fields"
    )
    agent_context: str = dspy.InputField(
        desc="Context about the affected agent: hostname, OS, role (e.g., web server, DB)"
    )

    # ── Outputs ───────────────────────────────────────────────────────────────
    severity: str = dspy.OutputField(
        desc="Effective severity after context analysis: critical / high / medium / low"
    )
    threat_category: str = dspy.OutputField(
        desc=(
            "Threat category aligned with MITRE ATT&CK tactics: "
            "initial_access / execution / persistence / privilege_escalation / "
            "defense_evasion / credential_access / discovery / lateral_movement / "
            "collection / command_and_control / exfiltration / impact / none"
        )
    )
    recommended_action: str = dspy.OutputField(
        desc=(
            "Specific recommended action for the SOC analyst. "
            "Include: isolate, block_ip, escalate, monitor, or ignore + reason."
        )
    )
    cve_references: str = dspy.OutputField(
        desc=(
            "Comma-separated CVE IDs if the alert relates to a known vulnerability. "
            "Format: CVE-YYYY-NNNNN. Return 'none' if not applicable."
        )
    )
    false_positive_likelihood: str = dspy.OutputField(
        desc="Likelihood this is a false positive: high / medium / low. Include brief reasoning."
    )


class SuricataAlertEnrichSignature(dspy.Signature):
    """
    Enrich a Suricata IDS/IPS alert with MITRE ATT&CK technique mapping
    and human-readable threat context.

    The alert comes from Suricata's eve.json (event_type=alert).
    It includes: signature, signature_id, category, severity (1-4),
    src_ip, src_port, dest_ip, dest_port, proto, action (allowed/blocked).

    Suricata severity scale (opposite of Wazuh):
      1 = Critical (highest), 2 = Major, 3 = Minor, 4 = Informational
    """

    # ── Inputs ────────────────────────────────────────────────────────────────
    suricata_alert_json: str = dspy.InputField(
        desc="Suricata alert event in JSON format from eve.json"
    )
    network_context: str = dspy.InputField(
        desc=(
            "Network context: known internal CIDR ranges, exposed services, "
            "traffic direction (inbound/outbound/lateral)"
        )
    )

    # ── Outputs ───────────────────────────────────────────────────────────────
    mitre_technique_id: str = dspy.OutputField(
        desc=(
            "Most relevant MITRE ATT&CK technique ID. "
            "Format: T followed by 4 digits and optional .NNN subtechnique. "
            "Example: T1190, T1110.001, T1046. Return 'unknown' if cannot determine."
        )
    )
    mitre_technique_name: str = dspy.OutputField(
        desc="Human-readable name of the MITRE technique, e.g. 'Exploit Public-Facing Application'"
    )
    attack_stage: str = dspy.OutputField(
        desc=(
            "Estimated kill-chain stage: reconnaissance / weaponization / "
            "delivery / exploitation / installation / c2 / actions_on_objectives"
        )
    )
    threat_summary: str = dspy.OutputField(
        desc=(
            "1-2 sentence plain-English summary of what this alert means "
            "in the context of an attack against the target network."
        )
    )
    recommended_action: str = dspy.OutputField(
        desc=(
            "Recommended immediate action: block_src_ip / block_dest_ip / "
            "monitor / escalate / ignore. Include which firewall/IPS rule to apply if relevant."
        )
    )


class CorrelationSignature(dspy.Signature):
    """
    Correlate a Wazuh HIDS alert (host event) with a Suricata NIDS alert
    (network event) that share common indicators (IP address, time window)
    to produce a unified MITRE ATT&CK-tagged incident report.

    This is the core PhD research module — it demonstrates how combining
    host and network telemetry allows AI to detect multi-stage attacks that
    neither source alone would detect.

    Example correlation scenario:
      Suricata: T1110.001 — SSH brute-force from 45.33.32.156
      Wazuh:    T1078     — Successful login from 45.33.32.156 on host web01
      Combined: T1078 credential compromise following brute-force (T1110.001)
                → much higher confidence than either alert alone.
    """

    # ── Inputs ────────────────────────────────────────────────────────────────
    wazuh_alert_summary: str = dspy.InputField(
        desc=(
            "Wazuh alert summary including rule.description, rule.level, "
            "rule.mitre.id, agent.name, agent.ip"
        )
    )
    suricata_alert_summary: str = dspy.InputField(
        desc=(
            "Suricata alert summary including signature, category, severity, "
            "src_ip, dest_ip, proto, action"
        )
    )
    shared_indicators: str = dspy.InputField(
        desc=(
            "Common indicators between the two alerts: shared IP addresses, "
            "time delta in seconds, any common ports or protocols"
        )
    )

    # ── Outputs ───────────────────────────────────────────────────────────────
    combined_severity: str = dspy.OutputField(
        desc=(
            "Combined incident severity taking both signals into account: "
            "critical / high / medium / low. "
            "Correlation of two medium alerts should usually elevate to high."
        )
    )
    mitre_tactic: str = dspy.OutputField(
        desc=(
            "Primary MITRE ATT&CK tactic for the combined incident, e.g. "
            "'Initial Access', 'Lateral Movement', 'Exfiltration'"
        )
    )
    mitre_technique_id: str = dspy.OutputField(
        desc="Primary MITRE ATT&CK technique ID for the correlated incident, e.g. T1078"
    )
    mitre_technique_name: str = dspy.OutputField(
        desc="Human-readable technique name, e.g. 'Valid Accounts'"
    )
    attack_narrative: str = dspy.OutputField(
        desc=(
            "2-4 sentence narrative explaining the likely attack scenario based on "
            "combining the two signals. Describe what the attacker is doing and "
            "why both alerts appearing together is significant."
        )
    )
    recommended_response: str = dspy.OutputField(
        desc=(
            "Prioritised list of response actions. Include: "
            "immediate (within 5 min), short-term (within 1 hr), "
            "long-term (within 24 hr) steps."
        )
    )
    ansible_playbook_hint: str = dspy.OutputField(
        desc=(
            "Name of the most appropriate Ansible incident response playbook "
            "to trigger from ansible/playbooks/incident_response/. "
            "Options: block_ip.yml / isolate_host.yml / rotate_credentials.yml / "
            "escalate_to_soc.yml / none"
        )
    )
