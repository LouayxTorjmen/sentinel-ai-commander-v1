#!/usr/bin/env python3
"""
Wazuh 4.14 IT Hygiene / Inventory Sync Script
==============================================

Workaround for a confirmed Wazuh 4.14 limitation: bulk inventory data
(packages, users, groups, networks, protocols) never flows from the
manager's wazuh-db into the OpenSearch indices that back the dashboard.

Processes and services use a separate real-time-delta pathway and
work fine; everything else stays stranded in per-agent SQLite files.

This script reads directly from
    /var/ossec/queue/db/<agent_id>.db           (sys_programs, sys_users, ...)
    /var/ossec/queue/db/global.db               (agent enumeration)

and pushes bulk documents to the Wazuh indexer via the `_bulk` API.

Designed to run inside the `sentinel-wazuh-manager` container on a
15-minute cron.  Uses deterministic MD5 document IDs so re-runs idempotently
upsert instead of creating duplicates.

INSTALLATION
------------
Install via `scripts/install_inventory_sync.sh` which will:
  - Copy this file to /usr/local/bin/sync_inventory.py inside the container
  - Chmod +x
  - Register a host cron entry running every 15 min
  - Run it once immediately to seed the indices

The script is intentionally self-contained and has no non-stdlib deps.
"""

import sqlite3
import subprocess
import json
import hashlib
import os
import datetime


INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200")
INDEXER_USER = os.environ.get("WAZUH_INVENTORY_SYNC_CREDS", "admin:Louay@2002")


# ─────────────────────────────────────────────────────────────────────────────
# Agent discovery — tries global.db first, falls back to client.keys
# ─────────────────────────────────────────────────────────────────────────────

def get_agents():
    """Return dict: agent_id (zero-padded str) -> {'name': ..., 'version': ...}"""
    agents = {}
    try:
        conn = sqlite3.connect("/var/ossec/queue/db/global.db")
        rows = conn.execute("SELECT id, name FROM agent WHERE id != 0").fetchall()
        conn.close()
        for aid, name in rows:
            agents[str(aid).zfill(3)] = {"name": name, "version": "v4.14.4"}
        if agents:
            return agents
    except Exception:
        pass

    try:
        with open("/var/ossec/etc/client.keys") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0].isdigit():
                    agents[parts[0].zfill(3)] = {
                        "name": parts[1],
                        "version": "v4.14.4",
                    }
    except Exception:
        pass

    return agents


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def base_doc(agent_id, agent_name):
    return {
        "agent": {"id": agent_id, "name": agent_name, "version": "v4.14.4"},
        "wazuh": {
            "cluster": {"name": "wazuh.manager"},
            "schema": {"version": "1.0"},
        },
    }


def push_bulk(index_name, bulk_lines):
    """Send a bulk request; return count of successful upserts."""
    if not bulk_lines:
        return 0
    payload = "\n".join(bulk_lines) + "\n"
    proc = subprocess.Popen(
        ["curl", "-sk", "-u", INDEXER_USER, "-X", "POST",
         f"{INDEXER_URL}/_bulk",
         "-H", "Content-Type: application/json",
         "--data-binary", "@-"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    stdout, _ = proc.communicate(input=payload.encode())
    try:
        resp = json.loads(stdout)
    except Exception:
        return 0
    if not resp.get("errors", True):
        return len(bulk_lines) // 2
    # Some docs failed — count successes and print the first failure reason
    # so schema-mismatch bugs stop being silent.
    items = resp.get("items", [])
    success = 0
    first_err = None
    for item in items:
        op_result = list(item.values())[0]
        if op_result.get("status", 500) < 400:
            success += 1
        elif first_err is None:
            err = op_result.get("error", {})
            first_err = f"{err.get('type','?')}: {err.get('reason','?')}"
    if first_err:
        rejected = len(items) - success
        print(f"    ↳ {rejected}/{len(items)} rejected — first error: {first_err}")
    return success


def open_db(agent_id):
    path = f"/var/ossec/queue/db/{agent_id}.db"
    if not os.path.exists(path):
        return None
    return sqlite3.connect(path)


def cols_of(conn, table):
    return [d[1] for d in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def clean(d):
    """Remove None / empty-string values from a dict (shallow)."""
    return {k: v for k, v in d.items() if v is not None and v != ""}


def safe_ip(value):
    """Return the value if it looks like a real IP, else None.

    OpenSearch's `ip` field type rejects empty strings and "0.0.0.0" as
    sentinels — those need to be omitted from the doc entirely, not sent
    as empty strings.
    """
    if value in (None, "", "0.0.0.0", "::", "unknown"):
        return None
    s = str(value).strip()
    # Must contain a dot (IPv4) or a colon (IPv6); rules out strings like "no"
    if "." not in s and ":" not in s:
        return None
    return s


def safe_bool(value):
    """Coerce syscollector's varied truthy strings to boolean, or None.

    sys_netproto.dhcp comes as 'enabled'/'disabled'/'unknown'/'BOOTP'/''.
    The indexer schema types `dhcp` as boolean and rejects anything else.
    """
    if value in (None, "", "unknown"):
        return None
    s = str(value).strip().lower()
    if s in ("enabled", "true", "yes", "1", "on"):
        return True
    if s in ("disabled", "false", "no", "0", "off"):
        return False
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Per-category sync functions
# ─────────────────────────────────────────────────────────────────────────────

def sync_packages(agents):
    index = "wazuh-states-inventory-packages-wazuh.manager"
    total = 0
    for aid, info in agents.items():
        conn = open_db(aid)
        if conn is None:
            continue
        try:
            rows = conn.execute("SELECT * FROM sys_programs").fetchall()
            cols = cols_of(conn, "sys_programs")
            bulk = []
            for row in rows:
                r = dict(zip(cols, row))
                uid = f"{aid}_{r.get('name','')}_{r.get('version','')}_{r.get('architecture','')}"
                doc = base_doc(aid, info["name"])
                doc["package"] = clean({
                    "name":         r.get("name", ""),
                    "version":      r.get("version", ""),
                    "architecture": r.get("architecture", ""),
                    "vendor":       r.get("vendor", ""),
                    "description":  r.get("description", ""),
                    "size":         r.get("size") or 0,
                    "priority":     r.get("priority", ""),
                    "source":       r.get("source", ""),
                    "multiarch":    r.get("multiarch", ""),
                    # `installed` intentionally omitted — not ISO-8601 in source
                })
                bulk.append(json.dumps({"index": {"_index": index, "_id": hashlib.md5(uid.encode()).hexdigest()}}))
                bulk.append(json.dumps(doc))
            total += push_bulk(index, bulk)
        except Exception as e:
            print(f"  [{aid}] packages error: {e}")
        finally:
            conn.close()
    print(f"  Packages pushed:   {total}")


def sync_users(agents):
    index = "wazuh-states-inventory-users-wazuh.manager"
    total = 0
    for aid, info in agents.items():
        conn = open_db(aid)
        if conn is None:
            continue
        try:
            rows = conn.execute("SELECT * FROM sys_users").fetchall()
            cols = cols_of(conn, "sys_users")
            bulk = []
            for row in rows:
                r = dict(zip(cols, row))
                uid = f"{aid}_{r.get('user_name','')}_{r.get('user_id','')}"
                doc = base_doc(aid, info["name"])
                doc["user"] = clean({
                    "name":      r.get("user_name", ""),
                    "full_name": r.get("user_full_name", ""),
                    "home":      r.get("user_home", ""),
                    "id":        str(r.get("user_id", "")),
                    "shell":     r.get("user_shell", ""),
                    "type":      r.get("user_type", ""),
                    "uuid":      r.get("user_uuid", ""),
                    "groups":    r.get("user_groups", ""),
                    "roles":     r.get("user_roles", ""),
                    "is_hidden": bool(r.get("user_is_hidden", 0)),
                    "is_remote": bool(r.get("user_is_remote", 0)),
                    "last_login": r.get("user_last_login"),
                    "group": clean({
                        "id":        r.get("user_group_id"),
                        "id_signed": r.get("user_group_id_signed"),
                    }),
                    "password": clean({
                        "last_change":                    r.get("user_password_last_change"),
                        "expiration_date":                r.get("user_password_expiration_date"),
                        "hash_algorithm":                 r.get("user_password_hash_algorithm", ""),
                        "inactive_days":                  r.get("user_password_inactive_days"),
                        "max_days_between_changes":       r.get("user_password_max_days_between_changes"),
                        "min_days_between_changes":       r.get("user_password_min_days_between_changes"),
                        "status":                         r.get("user_password_status", ""),
                        "warning_days_before_expiration": r.get("user_password_warning_days_before_expiration"),
                    }),
                    "auth_failures": {
                        "count":     r.get("user_auth_failed_count", 0),
                        "timestamp": r.get("user_auth_failed_timestamp"),
                    },
                })
                bulk.append(json.dumps({"index": {"_index": index, "_id": hashlib.md5(uid.encode()).hexdigest()}}))
                bulk.append(json.dumps(doc))
            total += push_bulk(index, bulk)
        except Exception as e:
            print(f"  [{aid}] users error: {e}")
        finally:
            conn.close()
    print(f"  Users pushed:      {total}")


def sync_groups(agents):
    index = "wazuh-states-inventory-groups-wazuh.manager"
    total = 0
    for aid, info in agents.items():
        conn = open_db(aid)
        if conn is None:
            continue
        try:
            rows = conn.execute("SELECT * FROM sys_groups").fetchall()
            cols = cols_of(conn, "sys_groups")
            bulk = []
            for row in rows:
                r = dict(zip(cols, row))
                uid = f"{aid}_{r.get('group_name','')}_{r.get('group_id','')}"
                doc = base_doc(aid, info["name"])
                doc["group"] = clean({
                    "id":          r.get("group_id"),
                    "name":        r.get("group_name", ""),
                    "description": r.get("group_description", ""),
                    "id_signed":   r.get("group_id_signed"),
                    "uuid":        r.get("group_uuid", ""),
                    "is_hidden":   bool(r.get("group_is_hidden", 0)),
                    "users":       r.get("group_users", ""),
                })
                bulk.append(json.dumps({"index": {"_index": index, "_id": hashlib.md5(uid.encode()).hexdigest()}}))
                bulk.append(json.dumps(doc))
            total += push_bulk(index, bulk)
        except Exception as e:
            print(f"  [{aid}] groups error: {e}")
        finally:
            conn.close()
    print(f"  Groups pushed:     {total}")


def sync_networks(agents):
    index = "wazuh-states-inventory-networks-wazuh.manager"
    total = 0
    for aid, info in agents.items():
        conn = open_db(aid)
        if conn is None:
            continue
        try:
            # Build iface_name -> (ipv4|ipv6 protocol type, dhcp) from sys_netproto,
            # so the network doc's `type` and `dhcp` come from the right table.
            proto_by_iface = {}
            for r in conn.execute("SELECT iface, type, dhcp FROM sys_netproto").fetchall():
                iface, ptype, dhcp = r
                # Prefer ipv4 entry if both ipv4 and ipv6 exist for same iface
                if iface not in proto_by_iface or ptype == "ipv4":
                    proto_by_iface[iface] = (ptype, dhcp)

            addrs = conn.execute("SELECT * FROM sys_netaddr").fetchall()
            acols = cols_of(conn, "sys_netaddr")
            bulk  = []
            for row in addrs:
                a    = dict(zip(acols, row))
                name = a.get("iface", "") or ""
                uid  = f"{aid}_{name}_{a.get('proto','')}_{a.get('address','')}"
                doc  = base_doc(aid, info["name"])
                doc["interface"] = {"name": name}

                # Only include fields that pass their type constraint.
                # `ip` fields reject empty strings and "0.0.0.0".
                net = {}
                ip = safe_ip(a.get("address"))
                if ip:
                    net["ip"] = ip
                nm = safe_ip(a.get("netmask"))
                if nm:
                    net["netmask"] = nm
                bc = safe_ip(a.get("broadcast"))
                if bc:
                    net["broadcast"] = bc

                # type/dhcp come from sys_netproto (ipv4/ipv6, enabled/disabled).
                ptype, dhcp_raw = proto_by_iface.get(name, (None, None))
                if ptype in ("ipv4", "ipv6"):
                    net["type"] = ptype
                dhcp_bool = safe_bool(dhcp_raw)
                if dhcp_bool is not None:
                    net["dhcp"] = dhcp_bool

                if not net:
                    # Nothing valid to send for this row — skip rather than
                    # inserting a doc with only interface.name
                    continue
                doc["network"] = net

                bulk.append(json.dumps({"index": {"_index": index, "_id": hashlib.md5(uid.encode()).hexdigest()}}))
                bulk.append(json.dumps(doc))
            total += push_bulk(index, bulk)
        except Exception as e:
            print(f"  [{aid}] networks error: {e}")
        finally:
            conn.close()
    print(f"  Networks pushed:   {total}")


def sync_protocols(agents):
    index = "wazuh-states-inventory-protocols-wazuh.manager"
    total = 0
    for aid, info in agents.items():
        conn = open_db(aid)
        if conn is None:
            continue
        try:
            rows = conn.execute("SELECT * FROM sys_netproto").fetchall()
            cols = cols_of(conn, "sys_netproto")
            bulk = []
            for row in rows:
                r = dict(zip(cols, row))
                name = r.get("iface", "") or ""
                uid  = f"{aid}_{name}_{r.get('type','')}"
                doc  = base_doc(aid, info["name"])
                doc["interface"] = {"name": name}

                # Schema: network.{type:keyword, gateway:ip, dhcp:boolean, metric:long}
                net = {}
                t = r.get("type")
                if t in ("ipv4", "ipv6"):
                    net["type"] = t
                gw = safe_ip(r.get("gateway"))
                if gw:
                    net["gateway"] = gw
                dhcp_bool = safe_bool(r.get("dhcp"))
                if dhcp_bool is not None:
                    net["dhcp"] = dhcp_bool
                if r.get("metric") is not None:
                    try:
                        net["metric"] = int(r["metric"])
                    except (TypeError, ValueError):
                        pass

                if not net:
                    continue
                doc["network"] = net

                bulk.append(json.dumps({"index": {"_index": index, "_id": hashlib.md5(uid.encode()).hexdigest()}}))
                bulk.append(json.dumps(doc))
            total += push_bulk(index, bulk)
        except Exception as e:
            print(f"  [{aid}] protocols error: {e}")
        finally:
            conn.close()
    print(f"  Protocols pushed:  {total}")


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[sync_inventory] Starting at {datetime.datetime.now().isoformat()}")
    agents = get_agents()
    if not agents:
        print("[sync_inventory] No agents found — nothing to do")
        raise SystemExit(0)
    print(f"[sync_inventory] Found {len(agents)} agent(s): {sorted(agents.keys())}")
    sync_packages(agents)
    sync_users(agents)
    sync_groups(agents)
    sync_networks(agents)
    sync_protocols(agents)
    print(f"[sync_inventory] Completed at {datetime.datetime.now().isoformat()}")
