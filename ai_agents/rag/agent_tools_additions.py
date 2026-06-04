# =============================================================================
# ADDITIONS TO ai_agents/rag/agent_tools.py
# =============================================================================
# Paste these functions into agent_tools.py BEFORE the TOOLS = {...} dict.
# Then add their entries to TOOLS and _PER_TOOL_COERCERS as shown at the bottom.
#
# These 7 tools fill the gaps identified in the architecture audit:
#   get_agent_details          — agent health/OS/version/last seen
#   get_agent_vulnerabilities  — CVEs from Wazuh's vuln module (replaces CVEScanner)
#   get_wazuh_rule             — rule definition lookup ("why did rule X fire?")
#   get_fim_events             — dedicated FIM query with path filter
#   execute_playbook           — run Ansible playbooks on command (2-phase confirmation)
#   get_active_blocks          — what is currently blocked, why was X banned
#   get_sca_results            — CIS benchmark / SCA compliance per agent
# =============================================================================

import time as _time   # already imported in agent_tools.py as time; alias avoids collision


# ── Internal helpers ──────────────────────────────────────────────────────────

def _agent_id_from_name(agent_name: str) -> Optional[str]:
    """Resolve a Wazuh agent name to its numeric ID.

    Returns None if the agent is not found.
    Used by tools that need the agent ID for Manager API calls
    (vulnerability module, SCA) rather than the name.
    """
    try:
        client = _get_client()
        data = client._manager_request(
            "GET", "/agents",
            params={"search": agent_name, "limit": 10},
        )
        agents = data.get("data", {}).get("affected_items", [])
        # Prefer exact name match over search ranking
        exact = next((a for a in agents if a.get("name") == agent_name), None)
        if exact:
            return str(exact["id"])
        return str(agents[0]["id"]) if agents else None
    except Exception:
        return None


# ─── Tool: get_agent_details ─────────────────────────────────────────


def get_agent_details(agent_name: str) -> Dict[str, Any]:
    """Get full status and metadata for a specific Wazuh agent.

    Returns OS, version, connection status, last keepalive, IP, and group
    membership. Use for 'show me the status of X', 'is agent Y online',
    'what OS is srv-sql running'.

    agent_name: exact agent name (e.g. 'srv-web', 'srv-ad-dns', 'srv-sql').
    """
    if not agent_name:
        return {"error": "agent_name required"}
    try:
        client = _get_client()
        data = client._manager_request(
            "GET", "/agents",
            params={"search": agent_name, "limit": 10},
        )
        agents = data.get("data", {}).get("affected_items", [])
        agent = next((a for a in agents if a.get("name") == agent_name), None)
        if agent is None:
            # Partial-name fallback: take closest match
            agent = agents[0] if agents else None
        if agent is None:
            return {"error": f"Agent '{agent_name}' not found. Use list_agents() to see all enrolled agents."}

        os_info = agent.get("os", {}) or {}
        return {
            "id":             agent.get("id"),
            "name":           agent.get("name"),
            "ip":             agent.get("ip"),
            "status":         agent.get("status"),
            "version":        agent.get("version"),
            "os_name":        os_info.get("name"),
            "os_platform":    os_info.get("platform"),
            "os_version":     os_info.get("version"),
            "os_arch":        os_info.get("arch"),
            "last_keepalive": agent.get("lastKeepAlive"),
            "date_enrolled":  agent.get("dateAdd"),
            "group":          agent.get("group") or [],
            "manager":        agent.get("manager"),
            "node_name":      agent.get("node_name"),
        }
    except Exception as exc:
        logger.warning("agent_tools.get_agent_details.failed: %s", exc)
        return {"error": str(exc)}


# ─── Tool: get_agent_vulnerabilities ─────────────────────────────────


def get_agent_vulnerabilities(
    agent_name: str,
    severity: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """Get CVE vulnerabilities detected by Wazuh on a specific agent.

    Queries Wazuh's built-in vulnerability module which scans installed
    packages against the NVD. More reliable than keyword NVD searches.
    Use for 'what CVEs does srv-sql have?', 'are there any critical vulns
    on agent X?', 'what needs patching?'.

    agent_name: exact agent name.
    severity: filter by CVSS severity ('critical', 'high', 'medium', 'low').
              Omit to return all severities.
    limit: max results (1-100). Default 20.
    """
    if not agent_name:
        return {"error": "agent_name required"}

    agent_id = _agent_id_from_name(agent_name)
    if agent_id is None:
        return {"error": f"Agent '{agent_name}' not found"}

    try:
        client = _get_client()
        params: Dict[str, Any] = {"limit": min(max(int(limit), 1), 100)}
        if severity:
            params["severity"] = severity.upper()

        data = client._manager_request(
            "GET", f"/vulnerability/{agent_id}",
            params=params,
        )
        items = data.get("data", {}).get("affected_items", [])
        total = data.get("data", {}).get("total_affected_items", len(items))

        vulns = []
        for v in items:
            vulns.append({
                "cve_id":      v.get("cve"),
                "severity":    v.get("severity"),
                "cvss_score":  v.get("cvss3_score") or v.get("cvss2_score"),
                "package":     v.get("name"),
                "version":     v.get("version"),
                "title":       (v.get("title") or "")[:200],
                "published":   v.get("published"),
                "updated":     v.get("updated"),
            })

        # Severity summary for quick overview
        from collections import Counter
        sev_counts = Counter(v["severity"] for v in vulns if v.get("severity"))

        return {
            "agent_name":      agent_name,
            "total":           total,
            "returned":        len(vulns),
            "severity_summary": dict(sev_counts),
            "vulnerabilities": vulns,
        }
    except Exception as exc:
        logger.warning("agent_tools.get_agent_vulnerabilities.failed: %s", exc)
        return {"error": str(exc)}


# ─── Tool: get_wazuh_rule ─────────────────────────────────────────────


def get_wazuh_rule(rule_id: str) -> Dict[str, Any]:
    """Look up a Wazuh rule definition by its ID.

    Returns the rule's description, level, groups, MITRE mappings,
    compliance standards (PCI-DSS, GDPR, HIPAA), and the file it lives in.
    Use for 'why did rule X fire?', 'what does rule 100601 detect?',
    'what MITRE technique is rule 550?'.

    rule_id: Wazuh rule ID as a string (e.g. '100601', '550', '5712').
    """
    if not rule_id:
        return {"error": "rule_id required"}
    try:
        client = _get_client()
        data = client._manager_request(
            "GET", "/rules",
            params={"rule_ids": str(rule_id)},
        )
        items = data.get("data", {}).get("affected_items", [])
        if not items:
            return {"error": f"Rule {rule_id} not found in Wazuh ruleset"}

        rule = items[0]
        return {
            "id":          rule.get("id"),
            "description": rule.get("description"),
            "level":       rule.get("level"),
            "groups":      rule.get("groups", []),
            "mitre":       rule.get("mitre", {}),
            "filename":    rule.get("filename"),
            "gdpr":        rule.get("gdpr", []),
            "pci_dss":     rule.get("pci_dss", []),
            "hipaa":       rule.get("hipaa", []),
            "tsc":         rule.get("tsc", []),
            "nist_800_53": rule.get("nist_800_53", []),
        }
    except Exception as exc:
        logger.warning("agent_tools.get_wazuh_rule.failed: %s", exc)
        return {"error": str(exc)}


# ─── Tool: get_fim_events ─────────────────────────────────────────────


def get_fim_events(
    agent_name: Optional[str] = None,
    path_contains: Optional[str] = None,
    time_window: str = "24h",
    limit: int = 30,
) -> Dict[str, Any]:
    """Search for File Integrity Monitoring (FIM/syscheck) events.

    Queries alerts with syscheck data — file additions, modifications,
    and deletions on monitored paths. Use for 'what files changed on X',
    'was /etc/passwd modified?', 'show me FIM events for the last hour',
    'what did the attacker change?'.

    agent_name: filter to a specific agent. Omit for all agents.
    path_contains: substring of the file path (e.g. '/etc/', 'cron', 'authorized_keys').
    time_window: '24h', '7d', '30d'. Default '24h'.
    limit: max results (1-100). Default 30.
    """
    body: Dict[str, Any] = {
        "size": min(max(int(limit), 1), 100),
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            {"range":  {"timestamp": {"gte": f"now-{time_window}"}}},
            # FIM events always have syscheck in their rule groups
            {"bool": {"should": [
                {"match_phrase": {"rule.groups": "syscheck"}},
                {"match_phrase": {"rule.groups": "fim"}},
            ], "minimum_should_match": 1}},
        ]}},
    }
    must = body["query"]["bool"]["must"]

    if agent_name:
        must.append({"match_phrase": {"agent.name": agent_name}})

    if path_contains:
        pkw = path_contains.strip()
        must.append({"bool": {"should": [
            {"wildcard": {"syscheck.path": {"value": f"*{pkw}*", "case_insensitive": True}}},
            {"match": {"full_log": pkw}},
        ], "minimum_should_match": 1}})

    try:
        data = _get_client()._indexer_request(
            "POST", "/wazuh-alerts-4.x-*/_search",
            json=body,
            headers={"Content-Type": "application/json"},
        )
    except Exception as exc:
        logger.warning("agent_tools.get_fim_events.failed: %s", exc)
        return {"total": 0, "events": [], "error": str(exc)}

    hits = data.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    events = []
    for h in hits.get("hits", []):
        src = h.get("_source", {})
        syscheck = src.get("syscheck", {}) or {}
        rule = src.get("rule", {}) or {}
        agent = src.get("agent", {}) or {}
        events.append({
            "timestamp":   src.get("timestamp") or src.get("@timestamp"),
            "agent_name":  agent.get("name"),
            "path":        syscheck.get("path"),
            "event":       syscheck.get("event"),      # added / modified / deleted
            "size_before": syscheck.get("size_before"),
            "size_after":  syscheck.get("size_after"),
            "md5_before":  syscheck.get("md5_before"),
            "md5_after":   syscheck.get("md5_after"),
            "uid_after":   syscheck.get("uid_after"),
            "gid_after":   syscheck.get("gid_after"),
            "perm_after":  syscheck.get("perm_after"),
            "rule_id":     rule.get("id"),
            "rule_desc":   rule.get("description"),
            "_id":         h.get("_id"),
            "_index":      h.get("_index"),
        })

    return {"total": total, "returned": len(events), "time_window": time_window, "events": events}


# ─── Tool: execute_playbook ───────────────────────────────────────────

# Playbooks exposed to the chatbot (subset of the full set — excludes
# destructive-without-IP playbooks that need richer context to be safe).
_CHATBOT_ALLOWED_PLAYBOOKS = {
    "block_ip",
    "incident_response",
    "win_incident_response",
    "fim_restore_response",
    "win_fim_restore_response",
    "harden_nginx_tls",
    "mysql_credential_response",
    "block_adcs_abuse",
    "block_dns_exfil",
    "brute_force_response",
    "win_brute_force_response",
    "lateral_movement_response",
    "win_lateral_movement_response",
}


def execute_playbook(
    playbook: str,
    target_host: str,
    confirmed: bool = False,
    source_ip: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute an Ansible response playbook on a target host (two-phase confirmation).

    CRITICAL — always call with confirmed=False first. This returns a
    preview of what will happen and asks the user to confirm. Only call
    with confirmed=True after the user explicitly says 'confirm', 'yes',
    'do it', 'go ahead', or similar.

    Available playbooks: block_ip, incident_response, win_incident_response,
    fim_restore_response, win_fim_restore_response, harden_nginx_tls,
    mysql_credential_response, block_adcs_abuse, block_dns_exfil,
    brute_force_response, win_brute_force_response, lateral_movement_response,
    win_lateral_movement_response.

    playbook: name of the playbook to run.
    target_host: Wazuh agent name (e.g. 'srv-web', 'srv-ad-dns'). Never 'all'.
    confirmed: False = show confirmation prompt, True = actually execute.
    source_ip: attacker IP to block (required for block_ip and brute force playbooks).
    reason: why you are running this (written to the incident audit log).
    """
    import requests as _req
    import uuid as _uuid
    from ai_agents.config import get_settings

    s = get_settings()
    base_url = f"http://{s.ansible_runner_host}:{s.ansible_runner_port}"

    # Validate playbook name
    if playbook not in _CHATBOT_ALLOWED_PLAYBOOKS:
        return {
            "error": (
                f"Playbook '{playbook}' is not available via the chatbot. "
                f"Available: {sorted(_CHATBOT_ALLOWED_PLAYBOOKS)}"
            )
        }

    # Validate target_host — never allow 'all'
    if not target_host or target_host.strip().lower() in ("all", "", "none"):
        return {"error": "target_host must be a specific agent name (e.g. 'srv-web'), never 'all'."}

    # Safety: block_ip and brute_force variants require a source IP
    _ip_required = {
        "block_ip", "brute_force_response", "win_brute_force_response",
        "lateral_movement_response", "win_lateral_movement_response",
    }
    if playbook in _ip_required and not source_ip:
        return {"error": f"Playbook '{playbook}' requires source_ip (the attacker's IP address)."}

    # Safety: never block loopback or management subnet
    if source_ip and (
        source_ip in ("127.0.0.1", "::1")
        or source_ip.startswith("10.60.")
    ):
        return {
            "error": f"Refusing to block protected IP '{source_ip}' (loopback or management subnet)."
        }

    # ── Phase 1: Confirmation prompt ─────────────────────────────────
    if not confirmed:
        action_lines = [f"**Playbook**: `{playbook}`", f"**Target host**: `{target_host}`"]
        if source_ip:
            action_lines.append(f"**Source IP to block**: `{source_ip}`")
        if reason:
            action_lines.append(f"**Reason**: {reason}")

        return {
            "status":  "pending_confirmation",
            "playbook": playbook,
            "target_host": target_host,
            "source_ip": source_ip,
            "message": (
                "⚠️ **Confirmation required** before executing:\n\n"
                + "\n".join(f"- {l}" for l in action_lines)
                + "\n\nReply **confirm** to proceed or **cancel** to abort."
            ),
        }

    # ── Phase 2: Execute ──────────────────────────────────────────────
    incident_id = f"chat_{_uuid.uuid4().hex[:8]}"
    extra_vars: Dict[str, Any] = {
        "target_hosts": target_host,
        "source_ip":    source_ip or "",
        "incident_id":  incident_id,
        "severity":     "high",
        "dry_run":      False,
    }
    if source_ip:
        extra_vars["block_ip_address"] = source_ip

    try:
        resp = _req.post(
            f"{base_url}/run",
            json={"playbook": playbook, "extra_vars": extra_vars},
            timeout=120,
        )
        resp.raise_for_status()
        result = resp.json()
    except Exception as exc:
        logger.error("agent_tools.execute_playbook.runner_failed: %s", exc)
        return {"error": f"Ansible runner call failed: {exc}", "playbook": playbook}

    # Write to Postgres incidents table for audit trail
    try:
        from ai_agents.database.db_manager import get_db
        from ai_agents.database.models import Incident, IncidentStatus, SeverityLevel
        with get_db() as db:
            db.add(Incident(
                id=incident_id,
                rule_id="chat_command",
                rule_description=reason or f"Chat-commanded: {playbook} on {target_host}",
                severity=SeverityLevel.HIGH,
                status=IncidentStatus.RESPONDING,
                source_ip=source_ip,
                analysis=(
                    f"Manually triggered via SENTINEL-AI chatbot. "
                    f"Playbook: {playbook}. Target: {target_host}. "
                    f"Reason: {reason or 'no reason given'}."
                ),
                recommended_action=playbook,
                playbook_executed=playbook,
                playbook_result=result,
                confidence_score=1.0,
                alert_data={"source": "chat_command", "target_host": target_host, "source_ip": source_ip},
            ))
    except Exception as db_exc:
        logger.warning("agent_tools.execute_playbook.db_write_failed: %s", db_exc)

    rc = result.get("rc", -1)
    ansible_status = result.get("status", "unknown")
    summary = result.get("summary", {})

    return {
        "status":         "executed",
        "incident_id":    incident_id,
        "playbook":       playbook,
        "target_host":    target_host,
        "source_ip":      source_ip,
        "rc":             rc,
        "ansible_status": ansible_status,
        "ok":             summary.get("ok", 0),
        "changed":        summary.get("changed", 0),
        "failed":         summary.get("failed", 0),
        "changed_tasks":  result.get("changed_tasks", [])[:5],
        "failed_tasks":   result.get("failed_tasks", []),
        "success":        rc == 0,
    }


# ─── Tool: get_active_blocks ──────────────────────────────────────────


def get_active_blocks(
    source_ip: Optional[str] = None,
    agent_name: Optional[str] = None,
    time_window: str = "7d",
) -> Dict[str, Any]:
    """Check what IP blocks are currently active in the SENTINEL-AI system.

    Queries the incidents database for executed block_ip and block_dns_exfil
    playbooks. Use for 'is 10.70.0.10 blocked?', 'why was this IP banned?',
    'what did you block today?', 'show me all active blocks'.

    source_ip: check if a specific IP is blocked (e.g. '10.70.0.10').
    agent_name: filter blocks on a specific agent. Omit for all agents.
    time_window: '24h', '7d', '30d'. Default '7d'.
    """
    from datetime import datetime, timedelta
    from ai_agents.database.db_manager import get_db
    from ai_agents.database.models import Incident

    try:
        unit = time_window[-1].lower()
        n    = int(time_window[:-1])
        delta = {"m": timedelta(minutes=n), "h": timedelta(hours=n),
                 "d": timedelta(days=n)}.get(unit, timedelta(days=7))
    except (ValueError, IndexError):
        delta = timedelta(days=7)
    cutoff = datetime.utcnow() - delta

    _block_playbooks = ("block_ip", "block_dns_exfil", "brute_force_response",
                        "win_brute_force_response", "lateral_movement_response",
                        "win_lateral_movement_response")

    try:
        with get_db() as db:
            q = db.query(Incident).filter(
                Incident.created_at >= cutoff,
                Incident.playbook_executed.in_(_block_playbooks),
            )
            if source_ip:
                q = q.filter(Incident.source_ip == source_ip)
            rows = q.order_by(Incident.created_at.desc()).limit(50).all()

            blocks = []
            for r in rows:
                # Resolve target agent from alert_data if available
                alert_data = r.alert_data or {}
                target = (
                    alert_data.get("target_host")
                    or (alert_data.get("agent") or {}).get("name")
                    or "unknown"
                )
                if agent_name and target != agent_name:
                    continue
                blocks.append({
                    "incident_id":      r.id,
                    "blocked_ip":       r.source_ip,
                    "target_agent":     target,
                    "playbook":         r.playbook_executed,
                    "reason":           r.rule_description,
                    "blocked_at":       r.created_at.isoformat() if r.created_at else None,
                    "trigger":          "chat_command" if r.rule_id == "chat_command" else f"rule_{r.rule_id}",
                })

            if source_ip:
                is_blocked = any(b["blocked_ip"] == source_ip for b in blocks)
                return {
                    "queried_ip": source_ip,
                    "is_blocked": is_blocked,
                    "block_count": len(blocks),
                    "blocks": blocks,
                }

            return {
                "total_blocks": len(blocks),
                "time_window":  time_window,
                "blocks":       blocks,
            }
    except Exception as exc:
        logger.warning("agent_tools.get_active_blocks.failed: %s", exc)
        return {"error": str(exc)}


# ─── Tool: get_sca_results ────────────────────────────────────────────


def get_sca_results(
    agent_name: str,
    limit: int = 20,
) -> Dict[str, Any]:
    """Get Security Configuration Assessment (SCA/CIS benchmark) results for an agent.

    Wazuh SCA periodically checks agents against CIS benchmarks and reports
    passed/failed/not-applicable checks. Use for 'CIS compliance status of
    srv-web', 'what security checks failed on srv-sql', 'hardening status'.

    agent_name: exact agent name.
    limit: max checks to return (1-100). Default 20.
    """
    if not agent_name:
        return {"error": "agent_name required"}

    agent_id = _agent_id_from_name(agent_name)
    if agent_id is None:
        return {"error": f"Agent '{agent_name}' not found"}

    try:
        client = _get_client()

        # Get SCA policies for this agent
        policy_data = client._manager_request(
            "GET", f"/sca/{agent_id}",
            params={"limit": 10},
        )
        policies = policy_data.get("data", {}).get("affected_items", [])
        if not policies:
            return {
                "agent_name": agent_name,
                "message": "No SCA policies found for this agent. SCA may not be configured.",
                "policies": [],
            }

        # Gather checks from the first (most relevant) policy
        policy_id = policies[0].get("policy_id")
        checks_data = client._manager_request(
            "GET", f"/sca/{agent_id}/checks/{policy_id}",
            params={"limit": min(max(int(limit), 1), 100)},
        )
        checks = checks_data.get("data", {}).get("affected_items", [])
        total  = checks_data.get("data", {}).get("total_affected_items", len(checks))

        # Summary counts
        passed   = sum(1 for c in checks if c.get("result") == "passed")
        failed   = sum(1 for c in checks if c.get("result") == "failed")
        not_appl = sum(1 for c in checks if c.get("result") == "not applicable")

        # Compact check representation
        compact_checks = []
        for c in checks:
            compact_checks.append({
                "id":          c.get("id"),
                "title":       c.get("title"),
                "result":      c.get("result"),
                "description": (c.get("description") or "")[:200],
                "remediation": (c.get("remediation") or "")[:200],
                "rationale":   (c.get("rationale") or "")[:150],
            })

        return {
            "agent_name":   agent_name,
            "policy_name":  policies[0].get("name"),
            "policy_id":    policy_id,
            "total_checks": total,
            "returned":     len(compact_checks),
            "summary": {
                "passed":         passed,
                "failed":         failed,
                "not_applicable": not_appl,
                "score_pct":      policies[0].get("score"),
            },
            "checks": compact_checks,
        }
    except Exception as exc:
        logger.warning("agent_tools.get_sca_results.failed: %s", exc)
        return {"error": str(exc)}


# =============================================================================
# UPDATE THE TOOLS REGISTRY — add these lines to the TOOLS dict:
# =============================================================================
#
# TOOLS: Dict[str, Any] = {
#     "search_alerts":            search_alerts,
#     "count_alerts":             count_alerts,
#     "top_signatures":           top_signatures,
#     "list_agents":              list_agents,
#     "get_alert":                get_alert,
#     "get_incidents":            get_incidents,
#     "get_incident_details":     get_incident_details,
#     "search_archives":          search_archives,
#     "agent_inventory":          agent_inventory,
#     # ── Phase 3 additions ──────────────────────────────────────────
#     "get_agent_details":        get_agent_details,           # NEW
#     "get_agent_vulnerabilities": get_agent_vulnerabilities,  # NEW
#     "get_wazuh_rule":           get_wazuh_rule,              # NEW
#     "get_fim_events":           get_fim_events,              # NEW
#     "execute_playbook":         execute_playbook,            # NEW
#     "get_active_blocks":        get_active_blocks,           # NEW
#     "get_sca_results":          get_sca_results,             # NEW
# }
#
# =============================================================================
# Also add to _PER_TOOL_COERCERS so time_window and limit get normalised:
# =============================================================================
#
# _PER_TOOL_COERCERS = {
#     "search_alerts":             _coerce_search_alerts_args,
#     "count_alerts":              _coerce_search_alerts_args,
#     "top_signatures":            _coerce_search_alerts_args,
#     "search_archives":           _coerce_search_alerts_args,
#     "agent_inventory":           _coerce_search_alerts_args,
#     "get_incidents":             _coerce_search_alerts_args,
#     # Phase 3 additions — same coercer handles time_window + limit
#     "get_agent_vulnerabilities": _coerce_search_alerts_args,  # NEW
#     "get_fim_events":            _coerce_search_alerts_args,  # NEW
#     "get_active_blocks":         _coerce_search_alerts_args,  # NEW
#     "get_sca_results":           _coerce_search_alerts_args,  # NEW
# }
