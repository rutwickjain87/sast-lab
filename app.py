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
import re
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

# Allowlist: only valid hostnames and IPv4/IPv6 addresses are permitted.
_HOST_RE = re.compile(
    r"^(?:"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]{1,63}"  # hostname
    r"|(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
    r"|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"  # IPv6
    r")$"
)


@app.before_request
def setup():
    init_db()


# ── CWE-78: Command Injection (FIXED) ────────────────────────────────────────

@app.route("/ping")
def ping():
    """
    Ping a host and return the output.

    FIX (CWE-78): User-supplied host is now validated against a strict
    allowlist regex before use.  The subprocess call uses a list (not a
    shell string) so shell=True is no longer required, eliminating the
    command-injection vector entirely.
    """
    host = request.args.get("host", "127.0.0.1")

    # Validate host against allowlist pattern to reject shell metacharacters
    if not _HOST_RE.match(host):
        return jsonify({"error": "Invalid host"}), 400

    # FIXED: shell=False (default) + argument list — no shell injection possible
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
    app.run(debug=True, host="0.0.0.0", port=5000)