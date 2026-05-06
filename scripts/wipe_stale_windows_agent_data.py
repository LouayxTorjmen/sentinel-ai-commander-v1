#!/usr/bin/env python3
"""
Wipe stale alert and monitoring data for Windows agents whose IDs were
previously assigned to deleted Linux agents.

Affected IDs:
  079  Win10-agent           (reused; original Linux agent registered before 2026-05-05)
  081  WinServer2019-agent   (reused; same)
  083  Win11-agent-2         (reused; same)

What gets deleted:
  - wazuh-alerts-*       documents matching agent.id IN [079,081,083] AND @timestamp < CUTOFF
  - wazuh-monitoring-*   documents matching id      IN [079,081,083] AND timestamp  < CUTOFF
  - wazuh-archives-*     same (only if archives exist; will be 0 in this env)

NOT touched:
  - Agent 000 (manager itself)
  - Agents 014, 015, 078 (your real Linux agents, just disconnected)
  - Orphan agent IDs from older deleted agents (001, 003, 004, 005, 073, 075, 076,
    077, 080, 082) - they don't show up in your dashboard since you don't filter
    by them, so no point deleting

Usage:
  python3 wipe_stale_windows_agent_data.py            # dry-run, prints counts
  python3 wipe_stale_windows_agent_data.py --execute  # actually deletes
"""
import os
import sys
import json
import subprocess
from pathlib import Path

REPO = Path.home() / "sentinel-ai-commander"
ENV_FILE = REPO / ".env"

# Load .env
ENV = {}
for line in ENV_FILE.read_text().splitlines():
    if "=" in line and not line.strip().startswith("#"):
        k, _, v = line.partition("=")
        ENV[k.strip()] = v.strip()

INDEXER_PASS = ENV.get("WAZUH_INDEXER_PASSWORD", "")
INDEXER_PORT = ENV.get("PORT_WAZUH_INDEXER_REST_API", "50002")
INDEXER_URL = f"https://localhost:{INDEXER_PORT}"

REUSED_IDS = ["079", "081", "083"]
CUTOFF = "2026-05-05T00:00:00Z"  # Windows agents all registered on/after this date

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; DIM = "\033[2m"; RST = "\033[0m"


def curl_json(method, path, body=None):
    """Call OpenSearch API via curl (works around SSL cert issues)."""
    cmd = [
        "curl", "-sk", "-u", f"admin:{INDEXER_PASS}",
        "-X", method, f"{INDEXER_URL}{path}",
        "-H", "Content-Type: application/json",
    ]
    if body is not None:
        cmd += ["-d", json.dumps(body)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return {"error": f"curl failed: {r.stderr}"}
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"error": "non-json response", "raw": r.stdout[:500]}


def count(index_pattern, query):
    r = curl_json("POST", f"/{index_pattern}/_count", {"query": query})
    return r.get("count", -1)


def delete_by_query(index_pattern, query):
    """Returns dict with 'deleted', 'failures', 'took' fields on success."""
    return curl_json(
        "POST",
        f"/{index_pattern}/_delete_by_query?conflicts=proceed&wait_for_completion=true&refresh=true",
        {"query": query},
    )


def queries_for_id(agent_id):
    return {
        "alerts": {
            "bool": {
                "must": [
                    {"term": {"agent.id": agent_id}},
                    {"range": {"@timestamp": {"lt": CUTOFF}}},
                ],
            },
        },
        "archives": {
            "bool": {
                "must": [
                    {"term": {"agent.id": agent_id}},
                    {"range": {"@timestamp": {"lt": CUTOFF}}},
                ],
            },
        },
        # wazuh-monitoring-* uses 'id' (no agent. prefix) and 'timestamp' (not @timestamp)
        "monitoring": {
            "bool": {
                "must": [
                    {"term": {"id": agent_id}},
                    {"range": {"timestamp": {"lt": CUTOFF}}},
                ],
            },
        },
    }


def main():
    execute = "--execute" in sys.argv

    print(f"{C}════════════════════════════════════════════════════════════{RST}")
    print(f"  Stale Windows-agent data cleanup")
    print(f"  Cutoff:   {CUTOFF}")
    print(f"  IDs:      {REUSED_IDS}")
    print(f"  Mode:     {R + 'EXECUTE (will delete)' if execute else G + 'DRY-RUN (counts only)'}{RST}")
    print(f"{C}════════════════════════════════════════════════════════════{RST}\n")

    if not INDEXER_PASS:
        print(f"{R}ERROR: WAZUH_INDEXER_PASSWORD not set in .env{RST}")
        return 1

    # Dry-run: count per index per ID
    print(f"{C}=== Counts (what would be deleted) ==={RST}")
    totals = {"alerts": 0, "archives": 0, "monitoring": 0}
    per_id = {}
    for aid in REUSED_IDS:
        qs = queries_for_id(aid)
        a_count = count("wazuh-alerts-*", qs["alerts"])
        ar_count = count("wazuh-archives-*", qs["archives"])
        m_count = count("wazuh-monitoring-*", qs["monitoring"])
        per_id[aid] = {"alerts": a_count, "archives": ar_count, "monitoring": m_count}
        totals["alerts"] += max(0, a_count)
        totals["archives"] += max(0, ar_count)
        totals["monitoring"] += max(0, m_count)
        print(f"  {aid}: alerts={a_count:>6}  archives={ar_count:>4}  monitoring={m_count:>4}")
    print(f"{DIM}  ---{RST}")
    print(f"  TOTAL: alerts={totals['alerts']:>6}  archives={totals['archives']:>4}  monitoring={totals['monitoring']:>4}")

    if not execute:
        print(f"\n{Y}This was a dry-run. To actually delete, re-run with --execute{RST}")
        return 0

    print(f"\n{R}=== Executing delete ==={RST}")
    summary = {}
    for aid in REUSED_IDS:
        qs = queries_for_id(aid)
        print(f"\n  {C}Agent {aid}:{RST}")
        for kind, idx_pattern in [
            ("alerts",     "wazuh-alerts-*"),
            ("archives",   "wazuh-archives-*"),
            ("monitoring", "wazuh-monitoring-*"),
        ]:
            if per_id[aid].get(kind, 0) <= 0:
                print(f"    {DIM}skip {kind}: 0 docs{RST}")
                continue
            r = delete_by_query(idx_pattern, qs[kind])
            deleted = r.get("deleted", 0)
            failures = len(r.get("failures", []))
            took_ms = r.get("took", 0)
            summary.setdefault(kind, 0)
            summary[kind] += deleted
            print(f"    {kind}: deleted={deleted}  failures={failures}  took={took_ms}ms")
            if failures:
                for f in r.get("failures", [])[:3]:
                    print(f"      {R}failure: {str(f)[:200]}{RST}")
            if "error" in r:
                print(f"      {R}ERROR: {r.get('error')}{RST}")

    # Re-count to confirm
    print(f"\n{C}=== Post-delete verification ==={RST}")
    for aid in REUSED_IDS:
        qs = queries_for_id(aid)
        a_count = count("wazuh-alerts-*", qs["alerts"])
        m_count = count("wazuh-monitoring-*", qs["monitoring"])
        print(f"  {aid}: alerts remaining={a_count}  monitoring remaining={m_count}")

    print(f"\n{C}=== Summary ==={RST}")
    for kind, n in summary.items():
        print(f"  Deleted {n:>6} {kind} documents")

    # Sanity: confirm CURRENT (post-cutoff) data is intact
    print(f"\n{C}=== Current Windows-era data (sanity check, should be NON-zero) ==={RST}")
    for aid in REUSED_IDS:
        keep_query = {
            "bool": {
                "must": [
                    {"term": {"agent.id": aid}},
                    {"range": {"@timestamp": {"gte": CUTOFF}}},
                ],
            },
        }
        cur = count("wazuh-alerts-*", keep_query)
        print(f"  {aid}: alerts since cutoff = {cur}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
