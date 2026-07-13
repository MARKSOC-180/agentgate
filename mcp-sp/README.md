# MCP Security Profile (MCP-SP)

[![MCP-SP](https://img.shields.io/badge/MCP--SP-Level%203-brightgreen)](../SPEC.md)

**A vendor-neutral profile for securing, governing, and auditing [Model Context Protocol](https://modelcontextprotocol.io) tool calls.**

MCP standardized how AI agents discover and call tools. It deliberately says little about the **security, governance, and auditability** of those calls — and in production that gap is the #1 risk. MCP-SP fills it with a small, implementable set of controls plus an **interoperable, tamper-evident audit-record format**, so any host, gateway, or server can be gated uniformly and any auditor can verify what an agent did.

- **The spec:** [`SPEC.md`](../SPEC.md) — controls, audit-record format, and three conformance levels (Baseline / Governed / Assured).
- **This folder:** a **single-file, zero-dependency reference validator** and a set of **conformance vectors** every implementation should agree on.

> MCP-SP is intentionally **not tied to any product.** The validator below depends on nothing but the Python standard library — copy the one file and you can self-certify. (A fuller reference implementation, [AgentGate](../README.md), demonstrates Level 3 end to end, but you don't need it to adopt the profile.)

---

## Install (optional)

The validator is one self-contained file with **zero dependencies** — you can just copy `mcp_sp.py`. If you'd rather install it:

```bash
pip install mcp-sp        # provides the `mcp-sp` command
mcp-sp your_audit.ndjson --anchors your_anchors.ndjson --require 3
```

## Self-certify in one command

```bash
python mcp_sp.py your_audit.ndjson --anchors your_anchors.ndjson --require 3
# or, if installed:  mcp-sp your_audit.ndjson --anchors your_anchors.ndjson --require 3
```

It prints PASS/FAIL per control, the determined level, and a ready-to-paste badge:

```
MCP-SP conformance: Level 3 (Assured)
  PASS  §3 Audit-record schema: all required fields present
  PASS  §2.1 Policy: every record carries a decision of allow|block
  PASS  §2.2 Redaction: every record records redaction hits
  PASS  §2.6 Tamper-evident audit: chain intact, N records, no tampering
  PASS  §2.10 Identity & delegation: M record(s) carry a consistent identity/delegation context
  PASS  §2.3 Safety: every record carries a safety findings field
  PASS  §2.7 External anchoring: verified against K anchor(s); history intact

Badge (paste into your README):
  [![MCP-SP](https://img.shields.io/badge/MCP--SP-Level%203-brightgreen)](.../SPEC.md)
```

`--require N` exits non-zero below level N, so it drops straight into CI:

```yaml
# .github/workflows/mcp-sp.yml
- run: python mcp_sp.py audit.ndjson --anchors anchors.ndjson --require 3
```

`--json` emits a machine-readable result for tooling.

---

## Conformance vectors

`conformance_vectors/` holds the shared ground truth. `vectors.json` maps each fixture to the level a conformant validator MUST report:

| Vector | Anchors | Expected level |
|---|---|---|
| `valid_level1.ndjson` | – | 1 (Baseline) |
| `valid_level2.ndjson` | – | 2 (Governed) |
| `valid_level3.audit.ndjson` | `valid_level3.anchors.ndjson` | 3 (Assured) |
| `bad_anchor.audit.ndjson` | `bad_anchor.anchors.ndjson` | 2 (forged anchor rejected) |
| `valid_identity_level2.ndjson` | – | 2 (consistent §2.10 delegation context) |
| `valid_identity_triple_level2.ndjson` | – | 2 (3-hop chain: service → agent → user) |
| `bad_identity.ndjson` | – | 0 (forged identity: subject ≠ delegation tail) |
| `bad_identity_triple.ndjson` | – | 0 (forged initiator: actor ≠ delegation[0]) |
| `tampered.ndjson` | – | 0 (chain broken) |
| `missing_field.ndjson` | – | 0 (schema fails) |

> Note `bad_identity.ndjson`: its hash chain is **valid** — the forgery is *semantic* (the recorded `subject` doesn't match the delegation chain). MCP-SP rejects it anyway, so the audit log proves not just "untampered bytes" but a coherent who-acted-for-whom.

Regenerate them with `python make_vectors.py`. **If you implement MCP-SP in another language, run your implementation against these vectors — agreement is the bar for interoperability.**

---

## Implementing MCP-SP

1. Emit one audit record per `tools/call`, with the fields in [`SPEC.md` §3](../SPEC.md), hash-chained as specified.
2. Run `python mcp_sp.py` (or reimplement it — it's ~200 lines of stdlib) to confirm your level.
3. Add the badge to your README and tell us — open an issue/PR so we can list you as an implementer.

The more independent implementations whose audit logs interoperate, the stronger the profile. That's the whole point: **a contract, not a library.**

---

## Status & contributing

`v0.2`, still a draft. New in v0.2: a minimal **identity & delegation** model (§2.10) — principals carry grants and an on-behalf-of chain, and authorization is decided on the *intersection* of grants along the chain, so delegation can only **attenuate** authority, never amplify it. The validator now also checks that any recorded identity context is internally consistent.

Especially wanted: critique of the control set and the attenuation primitive, more conformance vectors, and implementations in other languages. Issues and PRs welcome.

Licensed under Apache-2.0.
