#!/usr/bin/env python3
"""
End-to-end test of all 10 chat tools through the /chat endpoint using
Cerebras. Saves each response and prints a per-test pass/fail summary.

Why Python and not bash: bash + JSON + double-quoted-strings + apostrophes
in answers breaks every time. Python handles it cleanly.

Usage:
    python3 test_chat_tools.py
"""
import json
import os
import subprocess
import time
from pathlib import Path

import requests

OUT = Path("/tmp/sentinel_test")
OUT.mkdir(exist_ok=True)
for f in OUT.glob("*.json"):
    f.unlink()

ENDPOINT = "http://localhost:50010/chat"
PROVIDER = "cerebras"
TIMEOUT = 180  # seconds per test


def run_in_container(code: str) -> str:
    """Run python in the ai-agents container, return stdout stripped."""
    r = subprocess.run(
        ["docker", "exec", "sentinel-ai-agents", "python3", "-c", code],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout.strip()


# ─── Resolve real IDs to use in tests 5 & 7 ──────────────────────────

print("Resolving real IDs...")

alert_id_index = run_in_container("""
from ai_agents.rag.agent_tools import _get_client
c = _get_client()
r = c._indexer_request('POST','/wazuh-alerts-4.x-*/_search',
    json={'size':1,'sort':[{'timestamp':{'order':'desc'}}]},
    headers={'Content-Type':'application/json'})
hits = r.get('hits',{}).get('hits',[])
if hits:
    print(hits[0]['_id'] + '|' + hits[0]['_index'])
""")
if "|" in alert_id_index:
    ALERT_ID, ALERT_INDEX = alert_id_index.split("|", 1)
else:
    ALERT_ID, ALERT_INDEX = "", "wazuh-alerts-4.x-*"

INCIDENT_ID = run_in_container("""
from ai_agents.database.models import SessionLocal, Incident
with SessionLocal() as db:
    row = db.query(Incident).order_by(Incident.created_at.desc()).first()
    print(str(row.id) if row else '')
""")
if not INCIDENT_ID:
    # Fallback: try the API endpoint
    try:
        r = requests.get("http://localhost:50010/incidents", timeout=10)
        if r.ok:
            data = r.json()
            arr = data if isinstance(data, list) else (data.get("incidents") or [])
            if arr:
                INCIDENT_ID = arr[0].get("id", "")
    except Exception:
        pass

print(f"  ALERT_ID    = {ALERT_ID!r}")
print(f"  ALERT_INDEX = {ALERT_INDEX!r}")
print(f"  INCIDENT_ID = {INCIDENT_ID!r}")
print("=" * 70)


# ─── Test cases ──────────────────────────────────────────────────────

# Each test: (id, expected_tool, question)
TESTS = [
    ("01_search_alerts", "search_alerts",
     "any sql injection attempts in the last 7 days?"),
    ("02_count_alerts", "count_alerts",
     "how many total alerts have been recorded in the last 24 hours?"),
    ("03_top_signatures", "top_signatures",
     "what are the top 10 most common alert signatures this week?"),
    ("04_list_agents", "list_agents",
     "which Wazuh agents are currently enrolled and what is their connection status?"),
    ("05_get_alert", "get_alert",
     f"fetch the full document details for the alert with id {ALERT_ID} from index {ALERT_INDEX}"),
    ("06_get_incidents", "get_incidents",
     "list all incidents the orchestrator has analyzed recently with their severity"),
    ("07_get_incident_details", "get_incident_details",
     f"give me the full record for incident {INCIDENT_ID}" if INCIDENT_ID
     else "give me the full record for the most recent incident"),
    ("08_search_archives", "search_archives",
     "search the archives index for events from source IP 192.168.49.131 in the last 7 days that did not trigger an alert"),
    ("09_agent_inventory", "agent_inventory",
     "what software packages are installed on the agent named auto-victim1-ubuntu?"),
    ("10_path_contains", "search_alerts",
     "are there any FIM events for files matching hello.txt in the last 7 days?"),
]


# ─── Run them ────────────────────────────────────────────────────────

results = []

for tid, expected, question in TESTS:
    label = f"{tid:30s} ({expected})"
    print(label, end=" ", flush=True)

    if tid == "07_get_incident_details" and not INCIDENT_ID:
        print("SKIP (no INCIDENT_ID found)")
        results.append((tid, "skip", "no INCIDENT_ID"))
        continue
    if tid == "05_get_alert" and not ALERT_ID:
        print("SKIP (no ALERT_ID found)")
        results.append((tid, "skip", "no ALERT_ID"))
        continue

    t0 = time.time()
    try:
        resp = requests.post(
            ENDPOINT,
            json={"message": question, "preferred_provider": PROVIDER},
            timeout=TIMEOUT,
        )
    except requests.Timeout:
        print(f"FAIL  (timeout >{TIMEOUT}s)")
        results.append((tid, "fail", f"timeout >{TIMEOUT}s"))
        continue
    except Exception as exc:
        print(f"FAIL  (exception {exc})")
        results.append((tid, "fail", str(exc)))
        continue

    dt = time.time() - t0

    if not resp.ok:
        print(f"FAIL  (HTTP {resp.status_code})")
        results.append((tid, "fail", f"HTTP {resp.status_code}"))
        continue

    try:
        d = resp.json()
    except Exception as exc:
        print(f"FAIL  (non-JSON response: {exc})")
        results.append((tid, "fail", "non-JSON"))
        continue

    (OUT / f"{tid}.json").write_text(json.dumps(d, indent=2))

    ag = d.get("agentic") or {}
    calls = ag.get("tool_calls") or []
    names = [c.get("name", "") for c in calls]
    answer = (d.get("answer") or "").replace("\n", " ").strip()
    answer_preview = answer[:120]

    if expected in names:
        matching = [c for c in calls if c.get("name") == expected]
        summary = matching[0].get("result_summary", "") if matching else ""
        print(f"PASS  [{summary}]  {dt:.1f}s")
        print(f"        ANSWER: {answer_preview}")
        results.append((tid, "pass", summary))
    elif not calls and answer:
        print(f"WARN  (answered without any tool, {dt:.1f}s)")
        print(f"        ANSWER: {answer_preview}")
        results.append((tid, "warn", "no tool call"))
    else:
        print(f"FAIL  (called {names}, expected {expected}, {dt:.1f}s)")
        print(f"        ANSWER: {answer_preview}")
        results.append((tid, "fail", f"wrong tool: {names}"))


# ─── Summary ─────────────────────────────────────────────────────────

print("=" * 70)
n_pass = sum(1 for _, s, _ in results if s == "pass")
n_warn = sum(1 for _, s, _ in results if s == "warn")
n_fail = sum(1 for _, s, _ in results if s == "fail")
n_skip = sum(1 for _, s, _ in results if s == "skip")
print(f"PASS={n_pass}  WARN={n_warn}  FAIL={n_fail}  SKIP={n_skip}  total={len(results)}")
print(f"Responses saved to: {OUT}/")
print()
print("Inspect any test:")
print(f"  cat {OUT}/01_search_alerts.json | python3 -m json.tool | less")
