"""
tests/test_app.py — Functional tests for the vulnerable Flask app.

These tests verify correct *behaviour*, not the presence of vulnerabilities.
They pass both before AND after the fix (the fix doesn't break functionality).

The SAST agent's job is to fix the security issue while keeping these green.
If the fix breaks any of these tests, the agent retries.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the app root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def client():
    """Provide a Flask test client with an initialised in-memory DB."""
    from app import app
    from db import init_db

    app.config["TESTING"] = True
    app.config["DATABASE_URL"] = "sqlite:///:memory:"

    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client


# ── Health check ──────────────────────────────────────────────────────────────

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


# ── User lookup ───────────────────────────────────────────────────────────────

def test_get_existing_user(client):
    """Should return alice's record for a valid username."""
    resp = client.get("/user?username=alice")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["username"] == "alice"
    assert data["email"] == "alice@example.com"


def test_get_user_not_found(client):
    """Unknown username should return 404."""
    resp = client.get("/user?username=nobody")
    assert resp.status_code == 404


def test_get_user_by_id(client):
    """Should return bob's record for ID 2."""
    resp = client.get("/user/2")
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "bob"


def test_get_user_by_id_not_found(client):
    """ID 999 should return 404."""
    resp = client.get("/user/999")
    assert resp.status_code == 404


# ── Calculator ────────────────────────────────────────────────────────────────

def test_calculate_addition(client):
    """Basic arithmetic should work."""
    resp = client.get("/calculate?expr=2%2B2")
    assert resp.status_code == 200
    assert resp.get_json()["result"] == 4


def test_calculate_multiplication(client):
    resp = client.get("/calculate?expr=6*7")
    assert resp.status_code == 200
    assert resp.get_json()["result"] == 42


def test_calculate_invalid_expression(client):
    """Invalid expression should return 400."""
    resp = client.get("/calculate?expr=not_a_number")
    assert resp.status_code == 400
