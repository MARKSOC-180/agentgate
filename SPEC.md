# MCP Security Profile (MCP-SP) — v0.2 (Draft)

> A vendor-neutral profile for securing, governing, and auditing **Model Context Protocol (MCP)** tool calls.
>
> Status: **Draft / Request for Comments.** This document defines a conformance profile that any MCP host, gateway, or server may implement. [AgentGate](./README.md) is the reference implementation.
>
> The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 0. Why this profile exists

MCP standardizes how AI agents discover and call tools. It deliberately says little about **security, governance, and auditability** of those calls. In production this gap is the #1 risk: an agent wired to real tools can leak secrets, act without authorization, take destructive actions, exhaust quotas, or leave no defensible record — silently.

MCP-SP defines a small, implementable set of controls and an interoperable **audit record format** so that:

1. operators can gate any MCP server uniformly, regardless of vendor;
2. auditors can verify what an agent did, with non-repudiation;
3. tools, hosts, and gateways can advertise and negotiate a **conformance level**.

MCP-SP is transport-agnostic (stdio, HTTP/SSE) and deployment-agnostic (in-process library, sidecar, or proxy).

---

## 1. Scope

MCP-SP governs the lifecycle of a single MCP `tools/call`:

```
caller ─▶ [MCP-SP control point] ─▶ tool/server
                  │
   pre-execution: authz · policy · safety scan · input redaction · quota
   decision:      allow │ block │ hold-for-approval (runtime only; see §3)
   post-execution: output redaction · audit append · anchor · alert · metering
```

A **control point** is any component that enforces this profile (host, gateway, or server middleware).

---

## 2. Controls

### 2.1 Policy & authorization (MUST)
A control point **MUST** evaluate every `tools/call` against an explicit policy before execution, supporting at minimum:
- allow/deny lists of tool names;
- tools that **MUST** require an authorized principal;
- tools classified as **destructive**, which **MUST NOT** auto-execute unless explicitly permitted or approved (§2.5);
- a global **kill-switch** that, when engaged, **MUST** block all calls.

A blocked call **MUST NOT** reach the downstream tool/server.

### 2.2 Secret & PII redaction (MUST)
A control point **MUST** redact secrets and PII in **both** tool-call inputs and tool results before they are logged, traced, or returned upstream. At minimum it **MUST** detect common credential formats (provider API keys, private keys) and common PII (email, payment card, government ID). Redaction **MUST** be deterministic and **MUST** record the count and category of each hit without storing the cleartext.

### 2.3 Dangerous-action scanning (SHOULD)
A control point **SHOULD** scan call parameters for high-risk intent (e.g. unconditional bulk deletes, destructive shell, command injection, SSRF, oversized financial operations) and assign a severity. A `critical` finding **SHOULD** escalate to a block.

### 2.4 Rate-limit & budget (SHOULD)
A control point **SHOULD** enforce per-tool and/or per-principal rate limits and call/cost budgets, to bound the blast radius of a runaway or compromised agent. Exceeding a limit **MUST** result in a block with a machine-readable reason.

### 2.5 Human-in-the-loop approval (SHOULD)
For designated tools, a control point **SHOULD** hold the call in a pending state and require an out-of-band human decision (approve/deny) before execution. This satisfies human-oversight requirements (e.g. EU AI Act Art. 14). An approved decision **MUST** be bound to a specific principal and call context.

### 2.6 Tamper-evident audit (MUST)
A control point **MUST** append one record per call to an append-only audit log, where each record embeds the cryptographic hash of the previous record (a hash chain). The log **MUST** be verifiable: any edit, deletion, or insertion **MUST** be detectable and locatable. Records **MUST NOT** contain redacted cleartext; they **MUST** instead store content digests.

### 2.7 External anchoring (SHOULD)
To resist tampering by a privileged operator who could rewrite the log *and* recompute the chain, a control point **SHOULD** periodically publish the chain head (count + head hash + timestamp) to an **independent** sink (e.g. external append-only store, webhook, notarization service). Verification **MUST** flag any history whose recomputed head no longer matches a previously published anchor.

### 2.8 Alerting (MAY)
A control point **MAY** emit a real-time notification (command/webhook) on block and/or `critical` events.

### 2.9 Locality (SHOULD)
Because MCP traffic routinely contains secrets, PII, and proprietary code, a control point **SHOULD** be deployable fully self-hosted, with **zero egress** of call content to third parties by default.

### 2.10 Identity & delegation (SHOULD)
"Who is calling" is rarely a single string: an agent usually acts **on behalf of** a user or service, and must never exceed what that subject is itself permitted to do. A control point **SHOULD** model a call's identity as:

- a **principal** — `{ id, type }`, where `type` is one of `user | service | agent`, holding a set of **grants** (capabilities / scopes);
- an optional **delegation chain** (`on_behalf_of`): the ordered principals the actor is acting for.

For tools gated by required scopes, authorization **MUST** be decided on the **effective grants**, defined as the **intersection of the grants of every principal in the delegation chain**. That is, **delegation MUST attenuate authority and MUST NOT amplify it**: an agent acting for a user gets at most `agent.grants ∩ user.grants`. The **subject** of the action is the final principal in the chain (whom the action is ultimately for). Chains of arbitrary depth **MAY** appear (e.g. `service → agent → user`); effective grants are still the intersection across **every** hop, and the audit record's `delegation` array **MUST** list the full ordered chain with `actor` equal to `delegation[0]` and `subject` equal to `delegation[-1]`.

When identity is present, the audit record (§3) **SHOULD** carry the subject, the delegation chain, and the effective grants relied upon, so that "who authorized this action, and on whose behalf" is reconstructable. This model is intentionally minimal (no full OAuth); richer attestation (OIDC, SPIFFE, signed tokens) **MAY** layer on top via the issuer of a principal.

---

## 3. Audit record format

Each audit record is a single JSON object (one per line; NDJSON). Fields:

| Field | Type | Req. | Description |
|---|---|---|---|
| `ts` | number | MUST | Unix timestamp (seconds). |
| `tool` | string | MUST | Tool name from `tools/call`. |
| `principal` | string\|null | MUST | Authenticated caller identity, or null. |
| `decision` | string | MUST | `allow` \| `block`. |
| `reasons` | string[] | MUST | Machine-/human-readable decision reasons. |

**Runtime `hold-for-approval` (§1):** A control point MAY pause a call pending human review without executing the tool. The audit record for that pause **MUST** use `decision: "block"` and **SHOULD** include `approval: { "id": "<id>", "status": "pending" }`. After approval, a subsequent call that executes **MUST** record `decision: "allow"` with `approval.status: "approved"` (or `block` + `denied`). The string `hold-for-approval` does not appear in stored audit records.
| `redaction_hits` | object | MUST | Map of `{category: count}` redacted. |
| `safety` | string[] | SHOULD | `"{severity}:{title}"` findings. |
| `input_sha256` | string | MUST | Digest of the (redacted) inputs. |
| `output_sha256` | string | MUST | Digest of the (redacted) output. |
| `duration_ms` | number | SHOULD | Execution wall time. |
| `prev_hash` | string | MUST | Hash of the previous record (`GENESIS` for the first). |
| `this_hash` | string | MUST | `SHA-256(prev_hash + "|" + canonical(body))`. |
| `identity` | object | MAY | Identity/delegation context (§2.10), see below. |

`canonical(body)` is the JSON serialization of all fields **except** `this_hash`, with keys sorted lexicographically. Additional fields beyond those listed (e.g. `identity`) are permitted and are included in the hash; a verifier hashes the entire body except `this_hash`.

**Cross-language rule (normative for validators):** The reference Python serializer is `json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)` — i.e. `", "` between entries and `": "` after keys. Numbers MUST use the same textual form as in the reference (e.g. `1.0` and `0.0`, not `1` / `0`). Implementers in other languages MUST reproduce byte-identical canonical strings for the conformance vectors.

When present, the optional `identity` object (§2.10) carries:

| Field | Type | Description |
|---|---|---|
| `subject` | string | Principal the action is ultimately for (tail of the delegation chain). |
| `actor` | string | The principal that initiated the call. |
| `delegation` | string[] | Ordered principal ids, actor first, subject last. |
| `granted` | string[] | Effective grants (intersection across the chain) relied upon. |

Records without `identity` remain fully valid at their level; identity is an optional extension, not a Level 1 requirement.

When present, optional governance extensions:

| Field | Type | Description |
|---|---|---|
| `limits` | object | §2.4 evidence: `{ "checked": true, "cost": number }` when rate/budget was evaluated. |
| `approval` | object | §2.5 evidence: `{ "id": string, "status": "pending" \| "approved" \| "denied" }` for human-in-the-loop. |

Verifiers MUST reject malformed `limits`/`approval` objects when present (see reference validator).

### 3.1 Anchor record

Each anchor is a single JSON object (one per line; NDJSON), chaining the published audit head:

| Field | Type | Description |
|---|---|---|
| `count` | number | Number of audit records at anchor time. |
| `audit_head` | string | `this_hash` of record number `count`. |
| `prev_anchor` | string | Previous anchor hash (`ANCHOR_GENESIS` for the first). |
| `anchor_hash` | string | `SHA-256(prev_anchor + "|" + canonical(body))`. |

---

## 4. Conformance levels

An implementation **MAY** advertise one of:

- **MCP-SP Level 1 — Baseline.** §2.1 Policy, §2.2 Redaction, §2.6 Audit. (The minimum for any production deployment.)
- **MCP-SP Level 2 — Governed.** Level 1 **plus** §2.3 Safety, §2.4 Limits, §2.5 Approval, and §2.10 Identity & delegation (SHOULD).
- **MCP-SP Level 3 — Assured.** Level 2 **plus** §2.7 Anchoring and §2.9 Locality, suitable for regulated/compliance contexts.

A conformant implementation **MUST** be able to produce, on request, a verifiable audit log per §3 and **MUST** document which level it meets.

---

## 5. Capability advertisement (MAY)

A control point **MAY** advertise its profile support in the MCP `initialize` response under an experimental capability key, so hosts can negotiate:

```jsonc
{
  "capabilities": {
    "experimental": {
      "mcp-sp": { "version": "0.2", "level": 3, "anchoring": true, "selfHosted": true }
    }
  }
}
```

---

## 5.1 Conformance self-test & badge

Claiming a level should cost one command, not a lengthy audit. The reference implementation ships a conformance checker that validates any MCP-SP audit log (per §3) and determines its level from evidence:

```bash
agentgate conformance your_audit.ndjson --anchors your_anchors.ndjson --require 3
```

It checks record schema (§3), decision validity (§2.1), redaction recording (§2.2), hash-chain integrity (§2.6), the safety field (§2.3), and external-anchor verification (§2.7), then prints the determined level and a ready-to-paste badge:

```
[![MCP-SP](https://img.shields.io/badge/MCP--SP-Level%203-brightgreen)](…/SPEC.md)
```

Any implementation that emits a §3 audit log — in **any** language — can run the checker (or reimplement it; it's ~200 lines of standard library) to self-certify and display its level. `--require N` exits non-zero below level N, so it drops straight into CI as a gate.

A **product-independent** copy of the checker lives in [`mcp-sp/mcp_sp.py`](./mcp-sp/) — a single file with zero dependencies (not even AgentGate) — alongside **conformance vectors** ([`mcp-sp/conformance_vectors/`](./mcp-sp/)) that every implementation should agree on. Adopting the profile requires nothing from any vendor.

## 6. Reference implementation

[AgentGate](./README.md) implements MCP-SP Level 3: a self-hosted, zero-dependency control plane that can run as an in-process library or as a drop-in stdio **proxy** in front of any existing MCP server, with policy, redaction, safety, rate-limit/budget, approval, alerting, hash-chained audit, and external anchoring — plus `verify`, compliance export, and Prometheus metrics.

Conformance vectors (audit/anchor format, redaction categories, severity taxonomy) are exercised by the AgentGate test suite.

---

## 7. Change process

This is a draft. Proposals, conformance vectors, and dissent are welcome via issues/PRs against this document. Material changes bump the minor version; the audit/anchor record format is considered stable within a major version.

---

*MCP-SP is an open, vendor-neutral profile. Contributions are licensed under the repository's Apache-2.0 license.*
