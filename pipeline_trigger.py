"""
Lightweight webhook listener — receives POST from SOAR playbook on_finish()
and runs run_cyberproof.py for the given container_id in a background thread.

Usage:
    python pipeline_trigger.py

SOAR on_finish() HTTP POST payload:
    POST http://<this-host>:5000/trigger
    Content-Type: application/json
    {"container_id": 9}
"""

import subprocess
import threading
import sys
import os
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _run_pipeline(container_id: int) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [PIPELINE] Starting container_id={container_id}")
    result = subprocess.run(
        [sys.executable, "run_cyberproof.py", "--container_id", str(container_id)],
        cwd=_SCRIPT_DIR,
    )
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if result.returncode == 0:
        print(f"[{ts}] [PIPELINE] Finished OK  container_id={container_id}")
    else:
        print(f"[{ts}] [PIPELINE] FAILED (rc={result.returncode})  container_id={container_id}")


@app.route("/trigger", methods=["POST"])
def trigger():
    data = request.get_json(silent=True) or {}
    container_id = data.get("container_id")

    if container_id is None:
        return jsonify({"error": "container_id is required"}), 400

    try:
        container_id = int(container_id)
    except (TypeError, ValueError):
        return jsonify({"error": "container_id must be an integer"}), 400

    threading.Thread(target=_run_pipeline, args=(container_id,), daemon=True).start()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [TRIGGER]  Accepted container_id={container_id}")
    return jsonify({"status": "started", "container_id": container_id}), 202


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    print(f"CyberProof pipeline trigger listening on http://0.0.0.0:5000")
    print(f"  POST /trigger  {{\"container_id\": <id>}}  — start pipeline")
    print(f"  GET  /health                             — liveness check")
    app.run(host="0.0.0.0", port=5000)
