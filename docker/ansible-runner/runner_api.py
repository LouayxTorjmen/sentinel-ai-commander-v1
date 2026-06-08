import os
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import ansible_runner

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
CORS(app)

RUNNER_BASE = os.getenv("RUNNER_BASE", "/runner")
ANSIBLE_BASE = os.getenv("ANSIBLE_BASE", "/ansible")

ALLOWED_PLAYBOOKS = None  # None = allow all playbooks


def build_outcome(task_name, lines, idx, ev):
    """Build a specific human-readable outcome from task name and extra_vars."""
    import re
    task_lower = task_name.lower()
    context_lines = lines[idx + 1:min(idx + 20, len(lines))]
    ctx = " ".join(context_lines)

    # Get IP — prefer extra_vars (always correct), fallback to stdout parsing
    src_ip = ev.get("source_ip") or ev.get("block_ip_address") or ""
    if not src_ip:
        m = re.search(r"\d+\.\d+\.\d+\.\d+", ctx)
        src_ip = m.group(0) if m else "unknown"

    # Get file path from stdout
    found_path = ""
    m = re.search(r"/(?:etc|var|tmp|home|usr|opt|proc)/[^\s'\"\\]+", ctx)
    if m:
        found_path = m.group(0)

    # Get stdout/cmd snippets
    found_stdout = ""
    m = re.search(r'"stdout":\s*"([^"]{3,100})"', ctx)
    if m:
        found_stdout = m.group(1).strip()

    found_cmd = ""
    m = re.search(r'"cmd":\s*"([^"]{3,150})"', ctx)
    if m:
        found_cmd = m.group(1).strip()

    # ── iptables block ──────────────────────────────────────────────────
    if "block ip" in task_lower or "sentinel_block" in task_lower or (
            "iptables" in task_lower and "block" in task_lower):
        return "iptables DROP added: {} blocked in SENTINEL_BLOCK chain".format(src_ip)

    if "save iptables" in task_lower:
        return "iptables rules saved — block for {} persisted to disk".format(src_ip)

    if "unblock" in task_lower or "at command" in task_lower:
        dur = ev.get("block_duration_seconds", 3600)
        return "Auto-unblock scheduled: {} unblocked after {}s".format(src_ip, dur)

    if "log block" in task_lower:
        return "Block logged: {} incident={}".format(src_ip, ev.get("incident_id", "?"))

    # ── Windows Firewall ─────────────────────────────────────────────────
    if "windows firewall" in task_lower or "new-netfirewallrule" in task_lower:
        d = "Inbound" if "inbound" in task_lower else (
            "Outbound" if "outbound" in task_lower else "In+Out")
        return "Windows Firewall {} BLOCK created for {}".format(d, src_ip)

    # ── file remove ──────────────────────────────────────────────────────
    if ("remove" in task_lower or "delete" in task_lower) and (
            "file" in task_lower or "cron" in task_lower or "shell" in task_lower):
        target = found_path or found_stdout or found_cmd or task_name
        return "File removed: {}".format(target)

    # ── privilege revoke ─────────────────────────────────────────────────
    if "revoke" in task_lower or "privilege" in task_lower or "grant" in task_lower:
        detail = found_stdout or found_cmd or "dvwa SELECT on infra_credentials"
        return "Privileges revoked: {}".format(detail[:100])

    # ── kill connections ─────────────────────────────────────────────────
    if "kill" in task_lower and ("connection" in task_lower or "process" in task_lower):
        detail = found_stdout or src_ip or "attacker sessions"
        return "Connections terminated: {}".format(detail[:100])

    # ── TLS hardening ────────────────────────────────────────────────────
    if "tls" in task_lower or "cipher" in task_lower or (
            "nginx" in task_lower and "config" in task_lower):
        return "nginx TLS hardened: ECDHE-only ciphers enforced, RSA disabled"

    if "reload" in task_lower and "nginx" in task_lower:
        return "nginx reloaded with hardened TLS configuration"

    if "restart" in task_lower or "reload" in task_lower:
        return "Service restarted: {}".format(task_name.split(":")[-1].strip())

    # ── AD CS ────────────────────────────────────────────────────────────
    if "certutil" in task_lower or "crl" in task_lower:
        detail = found_stdout or found_cmd or "forged certificate"
        return "Certificate action: {}".format(detail[:120])

    if "template" in task_lower or "setca" in task_lower:
        return "AD CS template SentinelVulnESC1 unpublished from CA"

    # ── dnsdist ──────────────────────────────────────────────────────────
    if "dnsdist" in task_lower or ("dns" in task_lower and "block" in task_lower):
        return "DoH exfil blocked: {} added to dnsdist block list".format(src_ip)

    # ── baseline restore ─────────────────────────────────────────────────
    if "baseline" in task_lower or "restore" in task_lower:
        return "Restored from baseline: {}".format(found_path or task_name)

    # ── evidence collection ──────────────────────────────────────────────
    if "snapshot" in task_lower or "evidence" in task_lower or "collect" in task_lower:
        return "Evidence collected: {}".format(found_path or task_name.split(":")[-1].strip())

    # ── generic fallback ─────────────────────────────────────────────────
    if found_stdout and len(found_stdout) > 5:
        return "Output: {}".format(found_stdout[:150])
    if found_cmd and len(found_cmd) > 5:
        return "Executed: {}".format(found_cmd[:150])
    return task_name


@app.route("/inventory")
def get_inventory():
    try:
        with open(f"{ANSIBLE_BASE}/inventory/hosts.ini") as f:
            return f.read(), 200, {"Content-Type": "text/plain"}
    except Exception as e:
        return str(e), 500

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "ansible-runner-api",
                    "timestamp": datetime.utcnow().isoformat()})


@app.route("/run", methods=["POST"])
def run_playbook():
    data = request.get_json(force=True)
    playbook = data.get("playbook")
    extra_vars = data.get("extra_vars", {})
    tags = data.get("tags", [])

    if not playbook:
        return jsonify({"error": "playbook field is required"}), 400
    if ALLOWED_PLAYBOOKS is not None and playbook not in ALLOWED_PLAYBOOKS:
        return jsonify({"error": "playbook '{}' not allowed".format(playbook),
                        "allowed": list(ALLOWED_PLAYBOOKS)}), 403

    playbook_path = "{}/playbooks/{}.yml".format(ANSIBLE_BASE, playbook)
    if not os.path.exists(playbook_path):
        return jsonify({"error": "playbook file not found: {}".format(playbook_path)}), 404

    logger.info("Running playbook: %s", playbook)
    try:
        runner_args = {
            "private_data_dir": RUNNER_BASE,
            "playbook": playbook_path,
            "inventory": "{}/inventory/hosts.ini".format(ANSIBLE_BASE),
            "extravars": extra_vars,
            "quiet": False,
        }
        if tags:
            runner_args["tags"] = ",".join(tags)

        result = ansible_runner.run(**runner_args)

        # Parse per-task outcomes from stdout
        import re
        changed_tasks = []
        failed_tasks = []
        try:
            stdout_text = ""
            if hasattr(result, "stdout"):
                stdout_obj = result.stdout
                if hasattr(stdout_obj, "read"):
                    stdout_text = stdout_obj.read()
                elif isinstance(stdout_obj, str):
                    stdout_text = stdout_obj

            lines = stdout_text.splitlines()
            current_task = ""

            for i, line in enumerate(lines):
                # Detect TASK header
                tm = re.match(r"TASK \[(.+?)\]", line)
                if tm:
                    current_task = tm.group(1).strip()
                    continue

                # Detect changed result
                cm = re.match(r"changed: \[([^\]]+)\]", line.strip())
                if cm and current_task:
                    host = cm.group(1)
                    outcome = build_outcome(current_task, lines, i, extra_vars)
                    changed_tasks.append({
                        "task": current_task,
                        "host": host,
                        "changed": True,
                        "outcome": outcome,
                    })
                    continue

                # Detect fatal/failed (non-ignored)
                fm = re.match(r"fatal: \[([^\]]+)\]: FAILED!", line.strip())
                if fm and current_task:
                    ignored = any("...ignoring" in lines[j]
                                  for j in range(i, min(i + 3, len(lines))))
                    if not ignored:
                        msg = ""
                        for j in range(i, min(i + 5, len(lines))):
                            if '"msg"' in lines[j]:
                                msg = lines[j][:150]
                                break
                        failed_tasks.append({
                            "task": current_task,
                            "host": fm.group(1),
                            "error": msg,
                            "ignore_errors": False,
                        })
        except Exception as e:
            logger.warning("Could not parse task stdout: %s", e)

        outcomes = [t["outcome"] for t in changed_tasks if t.get("outcome")]

        response = {
            "playbook": playbook,
            "status": result.status,
            "rc": result.rc,
            "stats": result.stats,
            "timestamp": datetime.utcnow().isoformat(),
            "changed_tasks": changed_tasks,
            "failed_tasks": [t for t in failed_tasks if not t.get("ignore_errors")],
            "summary": {
                "changed": len(changed_tasks),
                "failed": len([t for t in failed_tasks if not t.get("ignore_errors")]),
                "outcomes": outcomes,
            },
        }
        return jsonify(response), 200 if result.rc == 0 else 500

    except Exception as e:
        logger.exception("Error running playbook: %s", e)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
