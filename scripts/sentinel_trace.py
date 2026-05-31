#!/usr/bin/env python3
"""
sentinel_trace.py — Show the full chain of events for one incident.

Usage:
    python3 sentinel_trace.py <incident_id>
    python3 sentinel_trace.py --latest 5
    python3 sentinel_trace.py --rule-id 100231 --since 1h

What it shows for each incident:
    1. The triggering Wazuh alert (from wazuh-alerts-* in OpenSearch)
    2. Every sentinel_ai_* event (from wazuh-alerts-* matching
       rule 100501-100507)
    3. The DB row from `incidents` (severity, playbook, status)
    4. Per-agent activity rows (from ai_agents.AgentActivity table)
    5. Ansible runner log lines (parsed from runner.log if accessible)

Designed so an operator can paste one UUID and see the entire decision
path without joining 5 SQL queries by hand.

Run from the HOST (WSL2) — the script talks to the OpenSearch indexer
and the PostgreSQL DB over their published ports.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib3
from datetime import datetime, timezone, timedelta
from typing import Any

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─── Config ──────────────────────────────────────────────────────────
INDEXER_URL  = os.getenv("WAZUH_INDEXER_URL", "https://localhost:50002")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASSWORD", "")

PG_HOST = os.getenv("PG_HOST", "localhost")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DB   = os.getenv("PG_DB",   "sentinel_ai")
PG_USER = os.getenv("PG_USER", "sentinel_ai")
PG_PASS = os.getenv("PG_PASS", "")

# Colors for terminal output
class C:
    BOLD = "\033[1m"
    DIM  = "\033[2m"
    CYAN = "\033[36m"
    GRN  = "\033[32m"
    YEL  = "\033[33m"
    RED  = "\033[31m"
    BLU  = "\033[34m"
    MAG  = "\033[35m"
    RST  = "\033[0m"


def header(text: str, char: str = "═") -> None:
    bar = char * 78
    print(f"\n{C.CYAN}{bar}{C.RST}")
    print(f"{C.BOLD}{C.CYAN}  {text}{C.RST}")
    print(f"{C.CYAN}{bar}{C.RST}")


def section(text: str) -> None:
    print(f"\n{C.BOLD}{C.BLU}── {text} ──{C.RST}")


# ─── OpenSearch helpers ──────────────────────────────────────────────

def opensearch_search(body: dict, index: str = "wazuh-alerts-*") -> dict:
    """POST a search query to the indexer."""
    if not INDEXER_PASS:
        die("WAZUH_INDEXER_PASSWORD env var is required")
    r = requests.post(
        f"{INDEXER_URL}/{index}/_search",
        json=body,
        auth=(INDEXER_USER, INDEXER_PASS),
        headers={"Content-Type": "application/json"},
        verify=False, timeout=20,
    )
    r.raise_for_status()
    return r.json()


# ─── Trace assembly ──────────────────────────────────────────────────

def fetch_trigger_alert(incident_id: str) -> dict | None:
    """Find the original Wazuh alert that started this incident.

    Approach: feedback events carry triggering_rule_id + target_agent +
    timestamp. We pull the EARLIEST feedback for this incident_id,
    extract those fields, then look for a non-1005xx alert from the same
    agent + same rule_id within a 5-minute window before the feedback.
    """
    # 1. Get earliest feedback for this incident
    body = {
        "size": 1,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": "now-24h"}}},
            {"match_phrase": {"data.incident_id": incident_id}},
        ]}},
    }
    try:
        r = opensearch_search(body)
        hits = [h["_source"] for h in r.get("hits", {}).get("hits", [])]
    except Exception:
        return None
    if not hits:
        return None
    first = hits[0]
    data = first.get("data") or {}
    trig_rule = data.get("triggering_rule_id")
    target_agent = data.get("target_agent")
    feedback_ts = first.get("timestamp")
    if not (trig_rule and target_agent and feedback_ts):
        return None

    # 2. Find the original alert from same agent + rule in the 5 min before
    body2 = {
        "size": 1,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": "now-24h", "lte": feedback_ts}}},
            {"term": {"rule.id": str(trig_rule)}},
            {"match_phrase": {"agent.name": target_agent}},
        ]}},
    }
    try:
        r2 = opensearch_search(body2)
        hits2 = [h["_source"] for h in r2.get("hits", {}).get("hits", [])]
        return hits2[0] if hits2 else None
    except Exception:
        return None


def fetch_feedback_events(incident_id: str) -> list[dict]:
    """Find every sentinel_ai feedback event for this incident."""
    body = {
        "size": 100,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": "now-24h"}}},
            {"match_phrase": {"data.incident_id": incident_id}},
            {"prefix": {"rule.id": "1005"}},
        ]}},
    }
    try:
        r = opensearch_search(body)
        return [h["_source"] for h in r.get("hits", {}).get("hits", [])]
    except Exception:
        return []


def fetch_latest_incidents(n: int = 5) -> list[str]:
    """Return the N most recent incident_ids seen in feedback events."""
    body = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": "now-24h"}}},
            {"prefix": {"rule.id": "1005"}},
        ]}},
        "aggs": {
            "by_incident": {
                "terms": {
                    "field": "data.incident_id",
                    "size": n,
                    "order": {"latest": "desc"},
                },
                "aggs": {
                    "latest": {"max": {"field": "timestamp"}},
                },
            },
        },
    }
    try:
        r = opensearch_search(body)
        buckets = r.get("aggregations", {}).get("by_incident", {}).get("buckets", [])
        return [b["key"] for b in buckets if b["key"]]
    except Exception:
        return []


# ─── Display ─────────────────────────────────────────────────────────

def color_for_phase(phase: str) -> str:
    return {
        "dispatch_received":  C.BLU,
        "dispatch_skipped":   C.DIM,
        "decision_made":      C.CYAN,
        "dry_run_executed":   C.YEL,
        "playbook_executed":  C.GRN,
        "playbook_failed":    C.RED,
        "no_action":          C.DIM,
    }.get(phase, C.RST)


def print_trigger(alert: dict) -> None:
    section("Triggering Wazuh alert")
    if not alert:
        print(f"  {C.DIM}(not found — the incident_id may be feedback-only){C.RST}")
        return
    r = alert.get("rule") or {}
    a = alert.get("agent") or {}
    print(f"  timestamp   : {alert.get('timestamp', '?')}")
    print(f"  rule_id     : {r.get('id')}   level={r.get('level')}")
    print(f"  description : {r.get('description', '')}")
    print(f"  agent       : {a.get('name', '?')}   ip={a.get('ip', '?')}")
    if r.get("groups"):
        print(f"  groups      : {', '.join(r['groups'])}")
    if r.get("mitre", {}).get("id"):
        print(f"  mitre       : {', '.join(r['mitre']['id'])}")


def print_feedback_events(events: list[dict]) -> None:
    section(f"AI / Ansible chain ({len(events)} event{'s' if len(events) != 1 else ''})")
    if not events:
        print(f"  {C.DIM}(no AI feedback events found for this incident){C.RST}")
        return
    for ev in events:
        data = ev.get("data") or {}
        phase = data.get("phase", "?")
        ts = ev.get("timestamp", "?")
        clr = color_for_phase(phase)
        print(f"  {C.DIM}{ts}{C.RST}  {clr}{C.BOLD}{phase:22s}{C.RST}", end="")

        bits = []
        if data.get("playbook"):           bits.append(f"playbook={data['playbook']}")
        if data.get("decision_source"):    bits.append(f"src={data['decision_source']}")
        if data.get("ai_severity"):        bits.append(f"sev={data['ai_severity']}")
        if data.get("confidence"):         bits.append(f"conf={data['confidence']}")
        if data.get("ansible_rc") not in ("", None):
            bits.append(f"rc={data['ansible_rc']}")
        if data.get("skip_reason"):        bits.append(f"why={data['skip_reason']}")
        if data.get("failure_reason"):     bits.append(f"fail={data['failure_reason']}")
        if data.get("no_action_reason"):   bits.append(f"why={data['no_action_reason']}")
        print(" " + "  ".join(bits))


def print_summary(events: list[dict]) -> None:
    if not events:
        return
    section("Outcome")
    phases = [(e.get("data") or {}).get("phase", "?") for e in events]
    if "playbook_executed" in phases:
        ev = next(e for e in events if (e.get("data") or {}).get("phase") == "playbook_executed")
        data = ev.get("data") or {}
        rc = data.get("ansible_rc")
        if str(rc) == "0":
            print(f"  {C.GRN}{C.BOLD}✓ PLAYBOOK SUCCEEDED{C.RST}  "
                  f"({data.get('playbook')} on {data.get('target_agent')})")
        else:
            print(f"  {C.YEL}{C.BOLD}⚠ PLAYBOOK ran but rc={rc}{C.RST}")
    elif "playbook_failed" in phases:
        print(f"  {C.RED}{C.BOLD}✗ PLAYBOOK FAILED{C.RST}")
    elif "dry_run_executed" in phases:
        print(f"  {C.YEL}● DRY-RUN only (rule level 7-9){C.RST}")
    elif "no_action" in phases or "dispatch_skipped" in phases:
        print(f"  {C.DIM}○ no action taken{C.RST}")


# ─── Entrypoint ──────────────────────────────────────────────────────

def trace_one(incident_id: str) -> None:
    header(f"INCIDENT  {incident_id}")
    trigger = fetch_trigger_alert(incident_id)
    feedback = fetch_feedback_events(incident_id)
    print_trigger(trigger)
    print_feedback_events(feedback)
    print_summary(feedback)
    print()


def trace_latest(n: int) -> None:
    ids = fetch_latest_incidents(n)
    if not ids:
        print(f"{C.YEL}No incidents found in the last 24h.{C.RST}")
        return
    print(f"\n{C.BOLD}Latest {len(ids)} incident(s):{C.RST}\n")
    for iid in ids:
        print(f"  • {iid}")
    print()
    for iid in ids:
        trace_one(iid)


def die(msg: str) -> None:
    print(f"{C.RED}ERROR: {msg}{C.RST}", file=sys.stderr)
    sys.exit(1)


def main():
    p = argparse.ArgumentParser(description="Trace a SENTINEL-AI incident end-to-end")
    p.add_argument("incident_id", nargs="?", help="Incident UUID to trace")
    p.add_argument("--latest", type=int, metavar="N",
                   help="Trace the N most recent incidents instead")
    args = p.parse_args()

    if args.latest:
        trace_latest(args.latest)
    elif args.incident_id:
        trace_one(args.incident_id)
    else:
        p.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
