# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | ✅ |
| 0.1.x | best-effort |

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Email: **security@agentgate.dev** (replace with your security contact before public launch)

Include:
- Description and impact
- Steps to reproduce
- Affected version/commit
- Suggested fix (optional)

We aim to acknowledge within **48 hours** and provide a fix or mitigation timeline within **7 days** for confirmed issues.

## Scope

In scope:
- AgentGate control plane (`agentgate/*`)
- MCP-SP reference validator (`mcp-sp/mcp_sp.py`)
- Tamper-evidence / anchoring logic
- MCP stdio proxy (confused-deputy, log injection, bypass)

Out of scope:
- Downstream MCP servers you attach (report to their maintainers)
- LLM model safety / prompt attacks above the tool boundary
- Host misconfiguration (e.g. bypassing the proxy entirely)

## Safe harbor

We appreciate responsible disclosure and will credit reporters in the release notes (unless you prefer anonymity).

See also: [THREAT_MODEL.md](./THREAT_MODEL.md)
