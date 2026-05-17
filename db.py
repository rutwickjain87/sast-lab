# db.py
# CWE-89: SQL Injection
# Semgrep rule: python.lang.security.audit.formatted-sql-query
#
# VULNERABILITY: User-controlled input is concatenated directly into
# an SQL query string. An attacker can inject arbitrary SQL.
# e.g. username = "' OR '1'='1" bypasses authentication.

import sqlite3


def get_connection():
    return sqlite3.connect("app.db")


def get_user(username: str) -> dict | None:
    """Fetch a user record by username."""
    conn = get_connection()
    cursor = conn.cursor()

    # VULNERABLE: string concatenation builds the query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "email": row[2]}
    return None


def get_user_by_id(user_id: int) -> dict | None:
    """Fetch a user record by ID."""
    conn = get_connection()
    cursor = conn.cursor()

    # VULNERABLE: f-string interpolation in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "email": row[2]}
    return None


def init_db():
    """Create the users table and seed test data."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, email TEXT)"
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'alice', 'alice@example.com')"
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users VALUES (2, 'bob', 'bob@example.com')"
    )
    conn.commit()
    conn.close()
