# config.py
# CWE-798: Use of Hard-coded Credentials
# Semgrep rule: generic.secrets.security.detected-secret
#
# VULNERABILITY: Secret key and DB password are hardcoded in source.
# Anyone with repo access can read them. Should come from env vars.

SECRET_KEY = "super-secret-hardcoded-key-do-not-use-12345"
DATABASE_URL = "sqlite:///app.db"
DATABASE_PASSWORD = "admin123"
DEBUG = True
