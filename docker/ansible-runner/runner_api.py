#!/usr/bin/env python3
import os
import logging
import ansible_runner
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ansible-runner-api")

ANSIBLE_BASE = os.getenv("ANSIBLE_BASE", "/ansible")
RUNNER_BASE  = os.getenv("RUNNER_BASE", "/ansible")

ALLOWED_PLAYBOOKS = {
    # Linux playbooks
    "incident_response",
    "block_dns_exfil",
    "brute_force_response",
    "malware_containment",
    "lateral_movement_response",
    "vulnerability_patch",
    "file_quarantine_response",
    "compromised_user_response",
    "permissions_restore_response",
    "fim_restore_response",
    # Windows playbooks
    "win_incident_response",
    "win_brute_force_response",
    "win_malware_containment",
    "win_lateral_movement_response",
    "win_vulnerability_patch",
    "win_file_quarantine",
    "win_compromised_user_response",
    "win_permissions_restore_response",
    "win_fim_restore_response",
    "block_adcs_abuse",
    "harden_nginx_tls",
    "mysql_credential_response",
    "block_ip",
    "block_dns_exfil",
}

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "ansible-runner-api", "timestamp": datetime.utcnow().isoformat()})

@app.route("/run", methods=["POST"])
def run_playbook():
    data = request.get_json(force=True)
    playbook   = data.get("playbook")
    extra_vars = data.get("extra_vars", {})
    tags       = data.get("tags", [])

    if not playbook:
        return jsonify({"error": "playbook field is required"}), 400
    if playbook not in ALLOWED_PLAYBOOKS:
        return jsonify({"error": f"playbook '{playbook}' not allowed", "allowed": list(ALLOWED_PLAYBOOKS)}), 403

    playbook_path = f"{ANSIBLE_BASE}/playbooks/{playbook}.yml"
    if not os.path.exists(playbook_path):
        return jsonify({"error": f"playbook file not found: {playbook_path}"}), 404

    logger.info(f"Running playbook: {playbook}")
    try:
        runner_args = {
            "private_data_dir": RUNNER_BASE,
            "playbook": playbook_path,
            "inventory": f"{ANSIBLE_BASE}/inventory/hosts.ini",
            "extravars": extra_vars,
            "quiet": False,
        }
        if tags:
            runner_args["tags"] = ",".join(tags)
        result = ansible_runner.run(**runner_args)
        # Extract per-task outcomes for visibility
        task_outcomes = []
        changed_tasks = []
        failed_tasks = []
        try:
            for event in result.events:
                ev_data = event.get("event_data", {})
                task_name = ev_data.get("task", "")
                task_action = ev_data.get("task_action", "")
                event_type = event.get("event", "")
                res = ev_data.get("res", {})

                if event_type == "runner_on_ok" and ev_data.get("changed"):
                    detail = {
                        "task": task_name,
                        "host": ev_data.get("host", ""),
                        "changed": True,
                    }
                    # Extract meaningful outcome details per task type
                    if "block" in task_name.lower() or "iptables" in task_name.lower():
                        detail["outcome"] = f"IP block applied: {res.get('cmd', '')[:120]}"
                    elif "remove" in task_name.lower() or "delete" in task_name.lower():
                        detail["outcome"] = f"Removed: {res.get('stdout', res.get('cmd', ''))[:120]}"
                    elif "revoke" in task_name.lower() or "privilege" in task_name.lower():
                        detail["outcome"] = f"Privileges revoked: {res.get('stdout', '')[:120]}"
                    elif "firewall" in task_name.lower() or "New-NetFirewall" in str(res):
                        detail["outcome"] = f"Firewall rule created: {res.get('stdout', '')[:120]}"
                    elif "certutil" in task_name.lower() or "revoke" in task_name.lower():
                        detail["outcome"] = f"Certificate action: {res.get('stdout', '')[:120]}"
                    elif "kill" in task_name.lower() or "connection" in task_name.lower():
                        detail["outcome"] = f"Connection killed: {res.get('stdout', '')[:80]}"
                    elif "copy" in task_action or "template" in task_action:
                        detail["outcome"] = f"File written: {ev_data.get('task_path', '')}"
                    elif "shell" in task_action or "command" in task_action:
                        stdout = res.get("stdout", "")[:200]
                        if stdout:
                            detail["outcome"] = f"Output: {stdout}"
                    changed_tasks.append(detail)
                    task_outcomes.append(detail)

                elif event_type == "runner_on_failed":
                    failed_tasks.append({
                        "task": task_name,
                        "host": ev_data.get("host", ""),
                        "error": str(res.get("msg", res.get("stderr", "")))[:200],
                        "ignore_errors": ev_data.get("ignore_errors", False),
                    })
        except Exception as e:
            logger.warning(f"Could not parse task events: {e}")

        response = {
            "playbook": playbook,
            "status": result.status,
            "rc": result.rc,
            "stats": result.stats,
            "timestamp": datetime.utcnow().isoformat(),
            "changed_tasks": changed_tasks,
            "failed_tasks": [t for t in failed_tasks if not t["ignore_errors"]],
            "summary": {
                "changed": len(changed_tasks),
                "failed": len([t for t in failed_tasks if not t["ignore_errors"]]),
                "outcomes": [t.get("outcome", t["task"]) for t in changed_tasks if t.get("outcome")],
            },
        }
        return jsonify(response), 200 if result.rc == 0 else 500
    except Exception as e:
        logger.exception(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/playbooks", methods=["GET"])
def list_playbooks():
    return jsonify({"playbooks": list(ALLOWED_PLAYBOOKS)})

if __name__ == "__main__":
    port = int(os.getenv("ANSIBLE_RUNNER_PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
