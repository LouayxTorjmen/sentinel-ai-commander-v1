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
    "incident_response",
    "brute_force_response",
    "malware_containment",
    "lateral_movement_response",
    "vulnerability_patch",
    "file_quarantine_response",
    "compromised_user_response",
    "permissions_restore_response",
    "fim_restore_response",
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
            "extravars": extra_vars,
            "quiet": False,
        }
        if tags:
            runner_args["tags"] = ",".join(tags)
        result = ansible_runner.run(**runner_args)
        response = {
            "playbook": playbook,
            "status": result.status,
            "rc": result.rc,
            "stats": result.stats,
            "timestamp": datetime.utcnow().isoformat(),
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
