# Start

```bash
pip install -e .
agentgate start
```

That creates `agentgate.config.json` and a Cursor MCP snippet.

Point the config at your real MCP server (`--downstream "…"`), then:

```bash
agentgate proxy --config agentgate.config.json
```

Or one shot:

```bash
agentgate start --downstream "python my_mcp_server.py" --run
```

Feel it in the browser: [start.html](../web/start.html) · [danger.html](../web/danger.html)

Everything else (export, conformance, approvals) is there when you need it — not before.
