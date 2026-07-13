# Quickstart

```bash
pip install -e .
python demo.py                    # library mode
python demo_mcp.py                # MCP proxy + mock server
agentgate verify agentgate_audit.ndjson
agentgate conformance agentgate_audit.ndjson --require 2
```

## Drop-in MCP proxy

Point your MCP host at AgentGate instead of the raw server:

```json
{
  "mcpServers": {
    "my-tools": {
      "command": "agentgate",
      "args": ["proxy", "--config", "/path/to/agentgate.config.json"]
    }
  }
}
```

See [policy-templates/](../policy-templates/) for starter configs.

## MCP-SP self-certify

```bash
pip install mcp-sp
mcp-sp agentgate_audit.ndjson --anchors agentgate_anchors.ndjson --require 3
```

Spec: [SPEC.md](../SPEC.md) · Implementers: [mcp-sp/IMPLEMENTERS.md](../mcp-sp/IMPLEMENTERS.md)
