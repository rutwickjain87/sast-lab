# app.py — Deliberately Vulnerable Flask Application
#
# THIS FILE CONTAINS INTENTIONAL SECURITY VULNERABILITIES FOR TESTING.
# DO NOT DEPLOY. DO NOT USE IN PRODUCTION.
#
# Vulnerabilities planted:
#   CWE-78  — Command injection via subprocess shell=True   (ping endpoint)
#   CWE-89  — SQL injection via string concatenation        (see db.py)
#   CWE-22  — Path traversal via unsanitised filename       (see utils.py)
#   CWE-95  — Eval injection via eval()                     (see utils.py)
#   CWE-798 — Hardcoded credentials                         (see config.py)

from __future__ import annotations

import os
import subprocess
import tempfile

from flask import Flask, jsonify, request

from config import DATABASE_URL, SECRET_KEY
from db import get_user, get_user_by_id, init_db
from utils import calculate, read_log

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["DATABASE_URL"] = DATABASE_URL

# Use a writable temporary directory for the database so the app works
# even when the working directory is read-only (e.g., during testing).
_DB_PATH = os.path.join(tempfile.gettempdir(), "app.db")
os.environ.setdefault("APP_DB_PATH", _DB_PATH)


@app.before_request
def setup():
    init_db()


# ── CWE-78: Command Injection ─────────────────────────────────────────────────

# Allowlist of permitted hosts for the ping endpoint.
_PING_ALLOWLIST = {
    "127.0.0.1",
    "localhost",
}

@app.route("/ping")
def ping():
    """
    Ping a host and return the output.

    FIXED (CWE-78): User-supplied host is now validated against an allowlist
    and passed as a list argument (shell=False) to subprocess, preventing
    command injection via shell metacharacters.
    """
    host = request.args.get("host", "127.0.0.1")

    # Validate host against an allowlist to prevent command injection.
    if host not in _PING_ALLOWLIST:
        return jsonify({"error": "host not allowed"}), 400

    # FIXED: shell=False + list arguments — no shell interpretation possible.
    output = subprocess.check_output(
        ["ping", "-c", "1", host],
        shell=False,
        text=True,
    )
    return jsonify({"output": output})


# ── CWE-89: SQL Injection ─────────────────────────────────────────────────────

@app.route("/user")
def user():
    """Look up a user by username."""
    username = request.args.get("username", "")
    result = get_user(username)
    if result:
        return jsonify(result)
    return jsonify({"error": "not found"}), 404


@app.route("/user/<int:user_id>")
def user_by_id(user_id: int):
    """Look up a user by numeric ID."""
    result = get_user_by_id(user_id)
    if result:
        return jsonify(result)
    return jsonify({"error": "not found"}), 404


# ── CWE-22: Path Traversal ────────────────────────────────────────────────────

@app.route("/logs")
def logs():
    """Return contents of a named log file."""
    filename = request.args.get("file", "app.log")
    try:
        content = read_log(filename)
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"error": "log not found"}), 404


# ── CWE-95: Eval Injection ────────────────────────────────────────────────────

@app.route("/calculate")
def calc():
    """Evaluate a mathematical expression."""
    expression = request.args.get("expr", "1+1")
    try:
        result = calculate(expression)
        return jsonify({"result": result})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


# ── Health check ──────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)