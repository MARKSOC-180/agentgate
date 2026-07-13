# MCP-SP Implementers Registry

Independent implementations that emit MCP-SP audit records and self-certify with the reference validator.

## How to get listed

1. Emit one audit record per `tools/call` per [SPEC.md §3](../SPEC.md).
2. Run the validator and reach your target level:
   ```bash
   pip install mcp-sp   # or: python mcp-sp/mcp_sp.py
   mcp-sp your_audit.ndjson --anchors your_anchors.ndjson --require 3
   ```
3. Paste the badge into your README.
4. Open a PR adding your project to the table below (or an issue with repo link + level achieved).

## Reference validator

| Artifact | Path |
|---|---|
| Spec | [SPEC.md](../SPEC.md) |
| Python validator (zero deps) | [mcp_sp.py](./mcp_sp.py) |
| TypeScript validator | [stubs/ts/mcp_sp.ts](./stubs/ts/mcp_sp.ts) |
| Conformance vectors | [conformance_vectors/](./conformance_vectors/) |
| JSON Schema | [schema/](../schema/) |

### Canonical hash (cross-language)

Validators MUST produce the same `this_hash` as the Python reference. Rules:

1. Sort object keys lexicographically at every nesting level.
2. Serialize with `", "` and `": "` separators (Python `json.dumps` default).
3. Preserve float literals from the source record when hashing (e.g. `duration_ms: 1.0` → `"1.0"`, not `"1"`).

The TypeScript stub reads raw NDJSON lines to recover `.0` float hints; other ports should do the same or match Python `json.dumps` exactly.

## Implementers

| Project | Level | Notes |
|---|---|---|
| **[AgentGate](../README.md)** | **3 (Assured)** | Reference implementation — policy, redaction, safety, limits, approval, identity/delegation, anchoring, metering, threat intel. MCP stdio proxy. |
| *Your project* | ? | PR welcome |

## Conformance levels (reminder)

| Level | Name | Evidence in audit log |
|---|---|---|
| 1 | Baseline | §3 schema + hash chain + policy decision + redaction hits |
| 2 | Governed | Level 1 + `safety` field; SHOULD also record identity/limits/approval when used |
| 3 | Assured | Level 2 + verified external anchors |

> **Evidence vs declaration:** Some controls (self-hosted locality) cannot be proven from logs alone — implementations MAY declare them; validators distinguish evidence from declaration.
