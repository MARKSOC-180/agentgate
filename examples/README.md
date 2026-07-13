# AgentGate Examples

Two ways to adopt AgentGate. Both run inside your own environment — nothing leaves.

---

## 1. Library mode (`01_quickstart.py`)

Wrap your own tool functions and attach every control: policy, rate-limit/budget, human-in-the-loop approval, and real-time alerts.

```bash
python examples/01_quickstart.py
```

You'll see a refund get held for human approval, then execute once approved, with the whole thing on a verifiable audit chain.

---

## 2. Drop-in MCP proxy in front of the official filesystem server (`filesystem_mcp.config.json`)

This is the zero-code-change path. AgentGate sits in front of the official
[`@modelcontextprotocol/server-filesystem`](https://github.com/modelcontextprotocol/servers) server. Your MCP host keeps speaking plain MCP — AgentGate gates every `tools/call`.

**Requires:** Node/`npx` on the machine. Point `./sandbox` at the directory you want to expose.

Run it standalone:

```bash
agentgate proxy --config examples/filesystem_mcp.config.json
# or: python -m agentgate.mcp_proxy --config examples/filesystem_mcp.config.json
```

### Wire it into Cursor / Claude Desktop (`mcp.json`)

**Before** — host talks directly to the filesystem server:

```jsonc
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "./sandbox"]
    }
  }
}
```

**After** — same server, now gated by AgentGate:

```jsonc
{
  "mcpServers": {
    "filesystem": {
      "command": "agentgate",
      "args": ["proxy", "--config", "/abs/path/to/examples/filesystem_mcp.config.json"]
    }
  }
}
```

With this config:

- **reads** (`read_file`, `list_directory`, …) pass through (pre-authorized),
- **writes/edits/moves** (`write_file`, `edit_file`, `move_file`) are held for **human approval** — approve with `agentgate approvals approve <id>`,
- every response is **secret/PII-redacted**, every call is **rate-limited** and written to a **tamper-evident audit chain**,
- blocked / critical events fire an **alert**.

### Inspect what happened

```bash
agentgate verify                 # hash-chain integrity
agentgate approvals list --pending
agentgate export --out compliance_export   # auditor-ready Markdown + CSV
agentgate metrics                # Prometheus text for Grafana
agentgate report                 # self-contained HTML report
```
