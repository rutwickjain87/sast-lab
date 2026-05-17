# utils.py
# CWE-22:  Path Traversal  — read_log()
# CWE-95:  Eval Injection  — calculate()
# Semgrep: python.lang.security.audit.path-traversal-open
#          python.lang.security.audit.eval

import os


def read_log(filename: str) -> str:
    """
    Read a log file by name from the log directory.

    VULNERABILITY (CWE-22): filename comes directly from user input with
    no sanitisation. An attacker can pass '../../etc/passwd' to read
    arbitrary files outside the log directory.
    """
    log_dir = "/var/logs/app"
    # VULNERABLE: no path normalisation or prefix check
    path = os.path.join(log_dir, filename)
    with open(path) as f:
        return f.read()


def calculate(expression: str) -> float:
    """
    Evaluate a mathematical expression provided by the user.

    VULNERABILITY (CWE-95): eval() executes arbitrary Python code.
    An attacker can pass '__import__("os").system("rm -rf /")' to
    execute any system command with the app's privileges.
    """
    # VULNERABLE: eval() on unsanitised user input
    return eval(expression)  # noqa: S307
