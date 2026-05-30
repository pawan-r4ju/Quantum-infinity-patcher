# ──────────────────────────────────────────────────────────────
# QIP Agent — Sandboxed Security Scanner & Patcher
# ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

LABEL maintainer="QIP Team"
LABEL description="Quantum Infinity Patcher — sandboxed CVE scanner agent"

# Non-root user
RUN groupadd -g 1000 qip && useradd -u 1000 -g qip -m qip

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# ── Install Grype ──
ARG GRYPE_VERSION=0.82.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v${GRYPE_VERSION}

# ── Install Trivy ──
ARG TRIVY_VERSION=0.52.0
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

# ── Install pip-audit ──
RUN pip install --no-cache-dir pip-audit==2.7.3

# ── Agent code ──
WORKDIR /app
COPY src/agent/ /app/agent/
COPY pyproject.toml /app/

# Install agent dependencies (minimal)
RUN pip install --no-cache-dir pydantic>=2.0 pyyaml>=6.0

# ── Volume mount points ──
# /repo    — read-only bind of target repository
# /output  — writable output for patches/reports
# /vuln-db — read-only local vulnerability database
RUN mkdir -p /repo /output /vuln-db /skills && \
    chown -R qip:qip /output

# Switch to non-root
USER qip

# Entry point
ENTRYPOINT ["python", "-m", "agent.main"]
