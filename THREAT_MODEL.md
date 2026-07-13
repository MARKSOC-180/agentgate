# Threat Model — AgentGate MCP Control Plane

## Assets

| Asset | Why it matters |
|---|---|
| Audit log (`*.ndjson`) | Non-repudiation evidence; tampering breaks compliance |
| Anchor log | Independent proof audit history wasn't rewritten |
| Approval store | Human-in-the-loop authorization state |
| Policy config | Defines what agents may do |
| Tool call payloads | May contain secrets, PII, proprietary data |

## Trust boundaries

```
[MCP Host / LLM] ──stdio──▶ [AgentGate Proxy] ──stdio──▶ [MCP Server]
                                  │
                                  ▼
                          local audit / trace / anchors
                          (must NOT egress by default)
```

**Trusted:** Operator who configures policy, approves destructive actions, holds anchor storage.  
**Untrusted:** LLM prompts, tool arguments, downstream MCP server responses, end-user content in tool payloads.

## Threats & mitigations

| Threat | Mitigation |
|---|---|
| Prompt injection → tool abuse | `safety.py` pattern scan; policy deny/destructive gates; human approval |
| Agent exceeds delegated authority | §2.10 identity + grant intersection (attenuation) |
| Secret/PII exfil via logs or LLM context | Two-way `redact.py`; audit stores digests only |
| Silent log tampering | Hash-chained audit + external anchoring |
| Quota/cost exhaustion | `limits.py` budget + rate caps |
| Privilege escalation via delegation forgery | Validator checks identity actor/subject vs chain |
| Proxy bypass (host talks to MCP server directly) | **Deployment** — enforce proxy in host config; network policy |
| Compromised proxy process | Run non-root; read-only policy; separate anchor writer; file ACLs on `/data` |
| Fake MCP-SP badge | Independent validator + public vectors; don't trust self-assertion alone |

## Out of scope (v0.2)

- Prompt-level firewall (profile stays at tool-call boundary by design)
- Cryptographic signatures on identity principals (OIDC/SPIFFE hooks provided; attestation is implementer responsibility)
- Network encryption between proxy and downstream (use mTLS at infra layer)

## Hardening checklist

- [ ] Mount audit/anchor volumes with restricted UID
- [ ] Deny `shell_exec` / RCE tools unless explicitly required
- [ ] Enable `anchor_every` + off-box anchor replication
- [ ] Enable alerts on block + critical safety
- [ ] Rotate approval store access; audit who approved what
- [ ] Run `agentgate verify` + `mcp-sp --require 3` in CI
