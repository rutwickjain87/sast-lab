# Dockerfile — sandboxed test runner
#
# Used by run_tests_in_docker() to validate fixes in isolation.
# Key safety properties:
#   --network=none  at runtime (no internet egress, no data exfiltration)
#   Non-root user   (no privilege escalation)
#   Read-only mount for source (agent mounts fixed files at runtime)

FROM python:3.11-slim

WORKDIR /app

# Install deps as root, then drop to non-root for test execution
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Non-root user
RUN useradd -m testrunner
USER testrunner

# Source is mounted at runtime by the agent (not copied here)
# This lets the agent swap in the fixed files without rebuilding the image

CMD ["python", "-m", "pytest", "tests/", "-v", "--tb=short", "--no-header"]
