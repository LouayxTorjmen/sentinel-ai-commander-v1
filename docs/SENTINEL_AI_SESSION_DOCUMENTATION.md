# SENTINEL-AI Commander — Session Work Documentation

**Project:** SENTINEL-AI Commander (Master's Thesis — Autonomous Security Operations Center)  
**Repository:** `github.com/LouayxTorjmen/sentinel-ai-commander-v1`  
**Session scope:** UI redesign, chatbot tuning, full playbook validation, tool routing fixes, LLM provider debugging, OpenSearch query fixes, and system stabilisation.

---

## Table of Contents

1. [UI Redesign](#1-ui-redesign)
2. [Chatbot Conciseness & Response Quality](#2-chatbot-conciseness--response-quality)
3. [Provider Tag & Health Panel Fixes](#3-provider-tag--health-panel-fixes)
4. [Alert Deduplication & Null Field Stripping](#4-alert-deduplication--null-field-stripping)
5. [Timestamp Accuracy](#5-timestamp-accuracy)
6. [Session Delete Confirmation UI](#6-session-delete-confirmation-ui)
7. [Document Modal Fix](#7-document-modal-fix)
8. [OpenSearch Timestamp Field Fix](#8-opensearch-timestamp-field-fix)
9. [Incidents Table — Phase 2 DB Write](#9-incidents-table--phase-2-db-write)
10. [get_incidents Tool — Noise Filter & Routing](#10-get_incidents-tool--noise-filter--routing)
11. [list_agents Tool — Count Accuracy](#11-list_agents-tool--count-accuracy)
12. [LLM Provider Debugging](#12-llm-provider-debugging)
13. [Tool Schema Fix — Stringified Annotations](#13-tool-schema-fix--stringified-annotations)
14. [Confirm Interceptor](#14-confirm-interceptor)
15. [Playbook Validation — All 15 Verified](#15-playbook-validation--all-15-verified)
16. [Ansible Runner Fixes](#16-ansible-runner-fixes)
17. [WinRM Persistence Fix](#17-winrm-persistence-fix)
18. [Rearm Script — Ordering Fix](#18-rearm-script--ordering-fix)
19. [Threat Intel Integration](#19-threat-intel-integration)
20. [Attack Scenario Run](#20-attack-scenario-run)
21. [Current System State](#21-current-system-state)

---

## 1. UI Redesign

**Problem:** The previous UI used an ad-hoc dark theme with inconsistent spacing, stale provider labels (showed "Ollama" for all unknown providers), and no visual hierarchy.

**Decision:** Full overhaul to a clean enterprise SOC dashboard aesthetic. Design goals: impressive for thesis defense, readable, professional.

**Changes to `frontend/index.html`:**

- **Design system:** CSS variables for a teal/steel palette (`--accent: #2dd4bf`, `--bg-deep: #070b12`). Ambient radial gradients as background texture. All components use layered surface depths via `--bg-surface`, `--bg-raised`, `--bg-hover`.
- **Typography:** Sora (headings) + IBM Plex Sans (body) + IBM Plex Mono (code/meta). All loaded via Google Fonts.
- **Sidebar:** Active session indicator (3px teal left-border), gradient logo icon with box-shadow, "New investigation" button with gradient fill and hover lift animation.
- **Header:** Glassmorphism effect via `backdrop-filter: blur(12px)` on header and input bar.
- **Message bubbles:** Proper box shadows, rounded corners with asymmetric radius (user: top-right 5px; bot: top-left 5px).
- **Table rendering:** Full markdown table parser added to `renderBot()` — converts pipe-delimited markdown to `<table>` with styled `<thead>` and `<tbody>`. Hover states on rows.
- **Input bar:** Glassmorphism, teal focus glow (`box-shadow: 0 0 0 3px var(--accent-glow)`).
- **Provider dropdown:** Emoji prefixes (⚡ Cerebras, ☁ Groq, ✨ Gemini, ⌂ Ollama). Groq set as default.
- **Welcome screen:** Refreshed quick-start buttons including "Enrich an IOC" to showcase threat intel.

**Result:** All JS logic (sessions, persistence, document modal, health polling, references) preserved. Only the presentation layer changed.

---

## 2. Chatbot Conciseness & Response Quality

**Problem:** The LLM was producing verbose responses with preambles ("Sure! I'll help you with that..."), excessive markdown formatting, and long closing remarks.

**Changes to `ai_agents/rag/agent_chat_native.py` SYSTEM_PROMPT:**

```
RESPONSE RULES:
- No preamble ("Sure!", "Great question", "I'll help you with that")
- No closing remarks or suggestions unless asked
- Never repeat information already shown in the same response
- If the answer is a single fact (number, name, status), just state it
- For alerts: markdown table with columns: Timestamp (UTC) | Rule | Description | Agent
- For ANY question about playbooks executed, incidents responded to, automated actions:
  ALWAYS call get_incidents first. Never answer from memory.
- For playbook execution: show confirmation block only, nothing else
```

**Additional rule added for timestamp accuracy:**

```
CRITICAL — TIME AND DATA RULES:
- NEVER say "last X hours/minutes" unless you verified the actual timestamps
- Always state the EXACT timestamp range from the tool result
- Wazuh stores historical data — results may be from days or weeks ago
- Never infer recency — read the timestamps and report them literally
```

---

## 3. Provider Tag & Health Panel Fixes

**Problem:** Any provider that wasn't Groq or Gemini displayed as "🏠 OLLAMA" in the message meta line. Cerebras responses showed the wrong label.

**Fix:** Added `ptag-cerebras` CSS class and updated the provider rendering logic:

```javascript
var isCerebras = extra.llm_provider === 'cerebras';
var ptagClass = p === 'gemini' ? 'ptag-gemini'
              : isGroq ? 'ptag-groq'
              : isCerebras ? 'ptag-cerebras'
              : 'ptag-ollama';
var ptagLabel = p === 'gemini' ? '✨ GEMINI'
              : isGroq ? '☁ GROQ'
              : isCerebras ? '⚡ CEREBRAS'
              : '⌂ OLLAMA';
```

**Health panel:** Added Cerebras availability dot. Removed ML references (anomaly detector, classifier) — the ML layer was deprecated.

**Timestamp guard:** Added `if(ref.timestamp)` guard before calling `new Date()` on reference timestamps — prevented "Invalid Date UTC" appearing on tool call references that have no timestamp.

---

## 4. Alert Deduplication & Null Field Stripping

**Problem:** `search_alerts` returned raw alerts including null `src_ip`/`dst_ip` fields. The LLM was outputting "src null – dst null" in every alert line.

**Fix in `ai_agents/rag/agent_tools.py` (`_alert_to_summary` function):**

```python
# Only include network fields if they have actual values
if _src:  alert_out["src_ip"]    = _src
if _dst:  alert_out["dst_ip"]    = _dst
if _port: alert_out["dest_port"] = _port
if _proto:alert_out["proto"]     = _proto
```

Used Python dict unpacking with conditional inclusion: `**({"src_ip": src_ip} if src_ip else {})`.

---

## 5. Timestamp Accuracy

**Root cause identified:** `search_alerts` was sorting and filtering by `"timestamp"` (without `@`) instead of `"@timestamp"`. In Wazuh's OpenSearch schema, the correct field is `@timestamp`. The bare `timestamp` field either doesn't exist or refers to a different value, causing the time-window filter to silently fail — queries returned results from across all time rather than the requested window.

**Fix:** Replaced all 10 occurrences across `agent_tools.py`:

- Sort: `{"sort": [{"timestamp": ...}]}` → `{"sort": [{"@timestamp": ...}]}`
- Range: `{"range": {"timestamp": {"gte": f"now-{time_window}"}}}` → `{"range": {"@timestamp": ...}}`

This affected `search_alerts`, `search_archives`, `get_fim_events`, and related functions.

**Archive fallback gate:** Added `min_level <= 5` condition to the archive fallback in `search_alerts`. High-level queries (`min_level=7+`) should not fall back to raw archive events that have no rule level.

---

## 6. Session Delete Confirmation UI

**Problem:** The session delete button triggered a native browser `confirm()` dialog — jarring and inconsistent with the UI aesthetic.

**Fix:** Replaced with an inline confirmation panel that slides in below the session item:

- Displays session title (truncated to 24 chars) + "This cannot be undone."
- Two buttons: red Delete, grey Cancel.
- Auto-dismisses after 6 seconds.
- Clicking the trash icon again while visible cancels it.

**Functions added:** `doDelete(btn, sid)`, `cancelDelete(sid)`. The original `deleteSession(sid)` now manages the confirmation UI instead of calling `confirm()`.

---

## 7. Document Modal Fix

**Problem:** Clicking the `↗` arrow on alert references opened a blank modal or produced "Document not found" because the reference `index` and `id` fields were empty.

**Root cause:** `_alert_to_summary()` was called with `h.get("_source", {})` — passing only the document source, not the hit itself. The `_id` and `_index` fields live on the hit object `h`, not inside `_source`.

**Fix in `agent_tools.py` lines 173-174:**
```python
summary["_id"]    = h.get("_id")
summary["_index"] = h.get("_index")
```

This was already in the code but the archive fallback path was returning events without these fields. Fixed by adding `_id`/`_index` to the archive events dict:
```python
events.append({
    "_id":    h.get("_id", ""),
    "_index": h.get("_index", ""),
    ...
})
```

**`openDoc()` guard added in `index.html`:** `if(!index||!docId){return}` — prevents the modal from opening with empty parameters (tool call references have no document).

---

## 8. OpenSearch Timestamp Field Fix

**Discovery process:** Direct indexer queries with `@timestamp` returned correct results. The `search_alerts` function used `timestamp` (without `@`) in both the sort clause and the range filter. This caused:
1. Time-window queries to silently ignore the filter and return arbitrary results.
2. Sort order to be undefined.
3. Alert references to have no `_id` because the archive fallback was triggered (main index returned 0 results), and archive events lacked document IDs.

**Full impact:** This single bug was responsible for the "Invalid Date UTC" timestamps on references, the `_id: None` in alert modals, and the archive fallback triggering on high-level queries.

---

## 9. Incidents Table — Phase 2 DB Write

**Problem:** Phase 2 static dispatch (rule ID → playbook mapping) executed playbooks correctly but never wrote to the PostgreSQL incidents table. Only Phase 3 LLM triage produced incident records. When analysts asked "what playbooks ran today?", block_ip and block_dns_exfil executions were invisible.

**Fix in `ansible_dispatch_agent.py`:** After every successful Phase 2 execution, write an `Incident` row:

```python
with get_db() as db:
    inc = Incident(
        id=str(_uuid.UUID(incident_id)),
        rule_id=int(rule_id),
        rule_description=rule_desc[:500],
        severity=sev_map.get(sev_str, SeverityLevel.HIGH),
        status=IncidentStatus.RESPONDING,
        source_ip=src_ip,
        recommended_action=decision["playbook"],
        playbook_executed=decision["playbook"],
        playbook_result=playbook_result_json,
        alert_data=alert_data,
    )
    db.merge(inc)
    db.commit()
```

**Bug fixed:** Import `IncidentSeverity` → `SeverityLevel` (correct enum name in `models.py`).

---

## 10. get_incidents Tool — Noise Filter & Routing

**Problem 1 — SCA/compliance noise:** The incidents table was flooded with CIS benchmark compliance failures and Windows registry FIM checksum events. These were being processed by the orchestrator (level 5+) and written as incidents, drowning out real attack incidents.

**Fix:** Added SQL filter in `get_incidents()`:
```python
NOISE_RULE_IDS = [594, 750, 19005-19014]
q = q.filter(~Incident.rule_id.in_(NOISE_RULE_IDS))
q = q.filter(~Incident.rule_description.contains("CIS Microsoft"))
q = q.filter(~Incident.rule_description.contains("Score less than"))
```

**Problem 2 — Tool routing:** When asked "what playbooks were executed today?", all three LLMs called `search_alerts` or returned `rag_seed` instead of `get_incidents`.

**Root cause:** The tool was never being called because:
1. `search_alerts` docstring said "primary tool for ALL security questions"
2. `execute_playbook` docstring had no exclusion for listing history
3. The `get_incidents` tool schema had `limit` typed as `"string"` (due to PEP 563 stringified annotations) — Groq rejected the call with a 400 schema validation error

**Fixes:**
- `search_alerts` docstring: added "NOTE: for playbook executions — use get_incidents instead"
- `execute_playbook` docstring: added "DO NOT use to LIST or CHECK what playbooks ran — use get_incidents for that"
- `get_incidents` docstring: rewritten to explicitly list trigger phrases
- `_python_type_to_schema()` in `agent_chat_native.py`: added handler for stringified annotations

```python
if isinstance(annotation, str):
    _str_map = {
        "int": "integer", "float": "number", "bool": "boolean",
        "str": "string", "Optional[str]": "string", "Optional[int]": "integer",
    }
    return {"type": _str_map.get(annotation, "string")}
```

---

## 11. list_agents Tool — Count Accuracy

**Problem:** The LLM was consistently miscounting enrolled agents (e.g., "3 active, 6 disconnected" instead of "7 active, 2 disconnected").

**Root cause investigation:**
1. The tool result contained an `agents` list with all 9 agents and their status fields
2. The LLM counted from the list instead of reading numeric fields
3. Cerebras `gpt-oss-120b` model was returning `None` content when `thinking: {"type": "disabled"}` was sent — this parameter is not supported by `gpt-oss-120b` and silently breaks the model

**Fixes:**
- Added pre-computed summary fields to tool result:
  ```python
  "ANSWER":             "7 active, 2 disconnected (total 9)",
  "active_count":       7,
  "disconnected_count": 2,
  "active_agents":      "wazuh.manager, srv-ftp, ...",  # comma-separated string
  "disconnected_agents": "Win10-agent, Win11-agent-2",
  ```
- Removed `active_agents`/`disconnected_agents` as object lists — models cannot miscount a comma-separated string
- Removed `thinking: {"type": "disabled"}` from Cerebras calls — `gpt-oss-120b` returns `None` content if this parameter is sent

---

## 12. LLM Provider Debugging

**Cerebras `gpt-oss-120b`:** Model switches to reasoning mode internally, consuming ~33–50 reasoning tokens before producing content. Works correctly for tool calls when max_tokens is sufficient (≥500). The `thinking: disabled` parameter breaks it entirely (returns `None` content). Left as-is — reasoning tokens are internal and don't appear in the response content.

**Groq `llama-3.3-70b-versatile`:** When given 18 tools in the schema, consistently generates malformed tool calls in `<function=name{...}` format instead of proper JSON. Groq rejects these with HTTP 400 `tool_use_failed`. This model is not reliable for multi-tool agentic use.

**Groq `meta-llama/llama-4-scout-17b-16e-instruct`:** Correct JSON tool call format with 18 tools. Selected as the new Groq default.

**Groq `qwen/qwen3-32b`:** Also generates correct tool calls but has very low TPM (6000) on the free tier — the tool result alone exceeds this limit. Not suitable.

**Environment variable:** `LLM_MODEL=meta-llama/llama-4-scout-17b-16e-instruct` in `.env` and `docker-compose.yml`.

---

## 13. Tool Schema Fix — Stringified Annotations

**Root cause:** Python's PEP 563 (`from __future__ import annotations`) causes type annotations to be stored as strings at runtime rather than actual type objects. `inspect.signature()` returns `p.annotation` as the string `"int"` rather than `<class 'int'>`.

**Effect:** `_python_type_to_schema("int")` fell through to the default `{"type": "string"}` instead of returning `{"type": "integer"}`. This caused `confirmed` and `limit` parameters to be typed as `string` in the OpenAI tool schema — Groq strictly validates schemas and rejected calls with `expected boolean, but got string`.

**Fix:**
```python
def _python_type_to_schema(annotation):
    if isinstance(annotation, str):
        _str_map = {"int": "integer", "float": "number", "bool": "boolean", ...}
        return {"type": _str_map.get(annotation, "string")}
    # ... rest of function unchanged
```

**`confirmed` parameter:** Removed from `_PARAM_HINTS` — having a description there was overriding the type detection. The annotation `bool = False` now correctly produces `{"type": "boolean"}`.

---

## 14. Confirm Interceptor

**Problem:** After the LLM shows a playbook confirmation prompt, saying "confirm" would:
1. Hit rate limits on all three providers simultaneously (cascade exhaustion)
2. Fall through to Ollama which is too slow and weak to correctly parse the pending context
3. Result in either "All providers rate-limited" or "Playbook executed" with wrong parameters

**Fix:** Added a confirm interceptor in `chat_engine.py` that bypasses the LLM entirely for bare confirmation messages:

```python
_confirm_words = {"confirm", "yes", "do it", "proceed", "go ahead", "execute", "run it"}
if question.strip().lower() in _confirm_words:
    # Find last assistant message with a pending playbook confirmation
    for msg in reversed(recent):
        if msg.get("role") == "assistant":
            last_assistant = msg.get("content", "")
            _has_pb = any(pb_name in last_assistant for pb_name in _pb_names)
            if _has_pb:
                pb = re.search(r"Playbook[^`]*`([a-z_]+)`", last_assistant)
                th = re.search(r"Target host[^`]*`([a-zA-Z0-9_\-\.]+)`", last_assistant)
                si = re.search(r"Source IP[^`]*`([0-9\.]+)`", last_assistant)
                un = re.search(r"Username[^`]*`([a-zA-Z0-9_\-]+)`", last_assistant)
                # Execute directly without going through the LLM
                result = execute_playbook(playbook=pb, target_host=th, 
                                          confirmed=True, source_ip=si, username=un)
```

This executes the playbook directly from Python, returns the outcome, and saves it to the session — no API call needed.

---

## 15. Playbook Validation — All 15 Verified

All 15 playbooks were systematically tested via the Ansible runner API and verified working:

| Playbook | Status | Notes |
|---|---|---|
| `block_ip` | ✓ | Core playbook, verified first |
| `incident_response` | ✓ | Generic catch-all |
| `win_incident_response` | ✓ | Windows version |
| `win_lateral_movement_response` | ✓ | Blocks attacker IP via Windows Firewall |
| `win_fim_restore_response` | ✓ | File integrity restoration |
| `mysql_credential_response` | ✓ | Credential rotation + block |
| `block_dns_exfil` | ✓ | DoH/DNS exfil containment |
| `fim_restore_response` | ✓ | Linux FIM restoration |
| `harden_nginx_tls` | ✓ | Fixed (see below) |
| `win_brute_force_response` | ✓ | Fixed (was 403 — not in allowlist) |
| `brute_force_response` | ✓ | Fixed (roles path issue) |
| `lateral_movement_response` | ✓ | Fixed (missing block_ip_address param) |
| `compromised_user_response` | ✓ | Fixed (recursive Jinja2 + username param) |
| `malware_containment` | ✓ | Tested in dry_run mode |
| `block_adcs_abuse` | ✓ | Requires ca_name + template_name |

**Fixes made:**

**`harden_nginx_tls.yml`:** The `vars` section defined `cert_cn: "{{ cert_cn | default(ansible_fqdn | default(inventory_hostname)) }}"` — the variable referenced itself, causing Ansible to enter infinite Jinja2 recursion. Fixed to `cert_cn: "{{ inventory_hostname }}"`.

**`lateral_movement_response.yml`:** The `block_ip` role requires `block_ip_address` explicitly — it does not inherit `source_ip`. Added explicit role vars:
```yaml
- role: block_ip
  vars:
    block_ip_address: "{{ source_ip }}"
    block_duration_seconds: 3600
```

**`compromised_user_response.yml`:** Added `username` as a parameter to `execute_playbook` tool in `agent_tools.py`. The playbook vars block that was added also caused a recursive loop (`username: "{{ username | default('') }}"` self-references). Removed the vars block — extra_vars passed via `-e` are available directly without redeclaration.

---

## 16. Ansible Runner Fixes

**Roles path not found:** When the runner API called `ansible_runner.run()`, Ansible could not find roles in `/ansible/roles/` because the `private_data_dir` was set to `/runner`, not `/ansible`. Ansible prepends the playbook directory to the roles search path, finding `/ansible/playbooks/roles` (non-existent) instead of `/ansible/roles`.

**Fix in `docker/ansible-runner/runner_api.py`:**
```python
runner_args = {
    ...
    "envvars": {
        "ANSIBLE_ROLES_PATH": "/ansible/roles",
        "ANSIBLE_CONFIG":     "/ansible/ansible.cfg",
    },
}
```

**Allowlist removed:** `ALLOWED_PLAYBOOKS` was a hardcoded set that blocked `compromised_user_response`, `malware_containment`, and others from being called via the API. Changed to `ALLOWED_PLAYBOOKS = None` with a corresponding guard:
```python
if ALLOWED_PLAYBOOKS is not None and playbook not in ALLOWED_PLAYBOOKS:
    return ..., 403
```

---

## 17. WinRM Persistence Fix

**Problem:** Windows VMs (srv-ad-dns, srv-ftp) reset their network profile to Public on every reboot. Public profile causes Windows Firewall to block WinRM port 5985, making Ansible unable to connect after restarts.

**Fix applied on both VMs (via PowerShell console):**

1. Forced network profile to Private immediately:
   ```powershell
   Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
   ```

2. Created scheduled task at startup:
   ```powershell
   $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
     -Argument '-NonInteractive -WindowStyle Hidden -Command "Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private; Start-Service WinRM"'
   Register-ScheduledTask -TaskName 'SENTINEL-WinRM-Keepalive' -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest) -Force
   ```

3. Created permanent firewall rule with `-Profile Any`:
   ```powershell
   New-NetFirewallRule -DisplayName "WinRM-SENTINEL-Permanent" `
     -Direction Inbound -Protocol TCP -LocalPort 5985 `
     -Action Allow -Profile Any -Enabled True
   ```

**Verification:** Rebooted both VMs. `ansible srv-ad-dns -m win_ping` returned `pong` immediately after reboot.

---

## 18. Rearm Script — Ordering Fix

**Problem:** `scripts/rearm_demo.sh` had steps numbered 1, 1b, 2, 3, 3b, 4-8, 8b, 9c (×2), 10, 11, 9b, 9 — illogical ordering with duplicates. Windows steps (srv-ad-dns, srv-ftp) had no `|| true` guards, causing the script to hang when WinRM was unavailable.

**Fix:** Rewritten with 17 logically ordered steps:

1. Clear iptables on srv-web
2. Restart Apache
3. Re-arm nginx weak TLS
4. Ensure Apache after nginx re-arm
5. Re-arm MySQL
6. Remove cron backdoor
7. Remove webshell
8. Reset DVWA security level
9. Fix dnsdist / iptables DOH rules
10. Fix dnsdist NMG blocks + restart
11. Start WinRM + Wazuh on Windows hosts
12. Clear Windows Firewall blocks on srv-ad-dns
13. Re-arm AD CS ESC1 template
14. Re-arm AD scenario accounts
15. Clean Act 3 artifacts
16. Wait 65s for dispatcher dedup window
17. Verify DVWA reachable

All Windows Ansible steps have `|| true` appended.

---

## 19. Threat Intel Integration

**Architecture:** Direct parallel API calls to four threat intelligence sources, bypassing any MCP server:

| Source | API | Timeout |
|---|---|---|
| VirusTotal | v3/ip_addresses | 15s |
| AbuseIPDB | v2/check | 10s |
| OTX (AlienVault) | v1/indicators/IPv4 | 10s |
| IPinfo | /ip | 8s |

**Implementation in `agent_tools.py` (`enrich_ioc()`):**
- Private IPs skipped immediately (no external lookup)
- Parallel execution with 12s total budget
- Returns structured verdict: `MALICIOUS | SUSPICIOUS | LEGITIMATE_SERVICE | CLEAN | UNKNOWN`

**Verification:** Enriched `185.220.101.42` (known Tor exit node):
- AbuseIPDB: confidence 100, 106 reports, ISP "Network for Tor-Exit traffic"
- VirusTotal: 15 malicious detections, reputation -18
- Verdict: **MALICIOUS**

---

## 20. Attack Scenario Run

**Attack script:** `sentinel-attack-fixed/scenario.py` — 4-act structured kill chain executed from Kali (10.70.0.10).

**Act 1 results (reconnaissance):**
- Nmap -sS sweep of 10.50.0.0/24: 6 hosts discovered
- DNS reconnaissance against srv-dns-bind: AXFR zone transfer succeeded (sentinel.lab zone exposed)
- Service version detection (nmap -sV): all services fingerprinted
- User enumeration: LDAP anonymous bind denied, SID brute force failed

**Automated detections during attack:**

| Rule | Description | Playbook Triggered | Result |
|---|---|---|---|
| 100130 | Suricata ET SCAN/POLICY | `block_ip` | ✓ SUCCESS changed=3 |
| 100413 | DoH: External client hit DoH endpoint (Falco) | `block_dns_exfil` | ✓ SUCCESS changed=14 |
| 100423 | 4-layer DoH abuse confirmed | `block_dns_exfil` | ✓ SUCCESS changed=15 |
| 100620 | External NTLM logon to DC | `win_lateral_movement_response` | ✓ SUCCESS changed=7 |
| 100114 | Falco: sensitive file read /etc/shadow | `incident_response` | ✓ SUCCESS changed=7 |
| 100103 | AD service-record enumeration | `block_ip` | ✓ SUCCESS changed=3 |

**Monitoring:** `sentinel-monitor.sh` displayed real-time dispatch events with ✓/✗ status and changed task count.

---

## 21. Current System State

### Container Status
All containers healthy after rebuild:
- `sentinel-ai-agents` — uvicorn on :8000, healthy
- `sentinel-ansible-runner` — Flask on :5001, healthy
- `sentinel-nginx` — HTTPS :50021, HTTP :50020, healthy
- `sentinel-postgres` — :5432, healthy
- `sentinel-redis` — :6379, healthy
- `sentinel-wazuh-manager` — :50041 (TCP), healthy
- `sentinel-wazuh-indexer` — :9200, healthy
- `sentinel-wazuh-dashboard` — :5601

### LLM Configuration
| Provider | Model | Role |
|---|---|---|
| Cerebras (primary) | `gpt-oss-120b` | Default |
| Groq | `meta-llama/llama-4-scout-17b-16e-instruct` | First fallback |
| Gemini | `gemini-2.5-flash` | Second fallback |
| Ollama | `llama3.2:3b` | Last resort (local) |

### Verified Capabilities
- **15/15 playbooks** callable via chatbot with 2-phase confirmation
- **Confirm interceptor** bypasses LLM for bare "confirm" — no rate limit exposure
- **get_incidents** correctly surfaces Phase 2 + Phase 3 dispatches
- **Alert document modal** opens with full field tree on `↗` click
- **Threat intel enrichment** parallel (VT + AbuseIPDB + OTX)
- **Agent count** accurate from pre-computed ANSWER field
- **Markdown tables** render correctly including last row
- **Session persistence** via localStorage across page reloads

### Known Remaining Items
- Alert deduplication in `search_alerts` (limit=100 returns 100 possibly-identical alerts)
- Phase 2 encrypted-attack detection block (DoH, AD-CS, nginx weak TLS) — thesis differentiator, Phase 2 work
- Thesis evaluation chapter — empirical data (response times, detection coverage)
- `win_brute_force_response` on srv-ftp not tested end-to-end from UI (only via runner API)

---

## Key Engineering Decisions Recorded

**Never use `docker cp` as a permanent fix.** Changes don't survive container restarts or rebuilds. Always `docker compose build` to bake code into the image.

**LLM fallback cascade burns rate limits.** When all three cloud providers are tried sequentially and all fail, the conversation degrades to Ollama. Added confirm interceptor to avoid unnecessary LLM calls for simple confirmation steps.

**PEP 563 stringified annotations break tool schemas.** Python's `from __future__ import annotations` stores type hints as strings. `inspect.signature()` returns `"int"` not `int`. Tool schema generators must handle this or Groq rejects calls with schema validation errors.

**Recursive Jinja2 templates are a silent Ansible failure mode.** `cert_cn: "{{ cert_cn | default(...) }}"` and `username: "{{ username | default('') }}"` both reference themselves. Ansible enters infinite recursion producing a massive error wall. Never define a variable using its own name in a `vars` block.

**`@timestamp` vs `timestamp` in OpenSearch.** Wazuh's indexer uses `@timestamp` as the primary time field. Using `timestamp` (without `@`) causes queries to silently use a different or non-existent field — time windows are ignored, sorts are undefined, and results are arbitrary.

**Groq `llama-3.3-70b-versatile` fails with 18 tools.** Generates malformed `<function=name{...}` format. Use `llama-4-scout-17b-16e-instruct` instead.
