# AgentGate MCP proxy — hardened sidecar (non-root)
FROM python:3.12-slim AS base

RUN groupadd -r agentgate && useradd -r -g agentgate -d /app agentgate
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY agentgate/ agentgate/
COPY mock_mcp_server.py agentgate.config.json ./

RUN pip install --no-cache-dir -e . \
    && chown -R agentgate:agentgate /app

USER agentgate
ENV PYTHONUTF8=1 PYTHONIOENCODING=utf-8 \
    AGENTGATE_AUDIT=/data/audit.ndjson \
    AGENTGATE_TRACE=/data/trace.ndjson \
    AGENTGATE_ANCHORS=/data/anchors.ndjson

VOLUME ["/data"]
CMD ["agentgate", "proxy", "--config", "/data/config.json"]
