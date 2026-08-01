# Agent / MCP Security Questionnaire — Draft Bank

Replace `{COMPANY}`, `{ENV}`, `{POLICY_SUMMARY}` before sending to a customer reviewer.

---

## Identity & authorization

### Q1. How are AI agents authenticated and authorized to call tools / MCP servers?
**Draft:**  
`{COMPANY}` routes agent tool traffic through a self-hosted AgentGate control plane in `{ENV}`. Calls are attributed with actor/subject identity fields (MCP-SP identity profile) and evaluated against an explicit policy before reaching upstream tools. Shared long-lived secrets in prompts are discouraged; secrets are redacted at the gate when detected.

**Evidence:** `mcp_sp_conformance.json`, redacted `agentgate.config.json`, `compliance_export/audit_export.json` (sample).

### Q2. Is there a human-in-the-loop for high-risk actions?
**Draft:**  
Yes. Tools classified as destructive or irreversible are configured with `require_approval`. The upstream call is held until a human records an allow/deny decision; both the hold and the decision are written to the audit chain.

**Evidence:** audit rows with approval fields; policy excerpt listing gated tools.

---

## Data handling & egress

### Q3. Does agent tool-call content leave our / your VPC to a third-party SaaS?
**Draft:**  
AgentGate is deployed self-hosted with **zero egress of call content by default**. Audit logs remain under `{COMPANY}` control. Optional external anchoring (if enabled) is designed to publish hashes/receipts, not raw payloads — confirm current anchor config in the delivery README.

**Evidence:** deployment diagram / runbook note; config showing local audit paths.

### Q4. How is PII / secret leakage prevented in tool args and outputs?
**Draft:**  
Bidirectional redaction runs at the gate (including common secret patterns and regional PII patterns where configured). Redacted values appear in audit/export forms suitable for reviewers without exposing raw secrets.

**Evidence:** report section on redaction events; sample redacted audit lines.

---

## Audit & integrity

### Q5. What is logged for each tool invocation?
**Draft:**  
Per call: timestamp, tool name, policy decision, identity fields, approval state (if any), redaction markers, and integrity linkage (hash chain). Exports available as MD/CSV/JSON/CEF for GRC or SIEM import.

**Evidence:** `agentgate_report.html`, `compliance_export/*`.

### Q6. Can administrators silently edit history?
**Draft:**  
Audit records are hash-chained; `verify()` detects tampering of the local chain. For stronger anti-equivocation, optional external anchoring can be enabled (MCP-SP Level 3 path).

**Evidence:** `README_DELIVERY.txt` chain verify line; anchors file if Level 3.

### Q7. Do you map controls to SOC2 / GDPR / EU AI Act / HIPAA?
**Draft:**  
AgentGate publishes an assistive control mapping (access control, minimization, human oversight, audit logging, kill-switch). This supports questionnaire responses; it is **not** a certification of `{COMPANY}`’s full compliance program.

**Evidence:** AgentGate `docs/COMPLIANCE.md` mapping table (attach as needed).

---

## Runtime safety

### Q8. How do you stop runaway or abusive tool use?
**Draft:**  
Rate/budget limits and safety scanners can deny or hold calls (injection-like patterns, destructive signatures). A kill-switch can halt tool traffic without redeploying the agent application.

**Evidence:** policy limits section; deny/hold samples in audit export.

### Q9. What is the emergency disablement path?
**Draft:**  
Operators flip the gate kill-switch / deny-all policy template; new tool calls fail closed. Procedure documented in the runbook delivered with the Design Partner.

**Evidence:** runbook excerpt; deny-all policy template name.

---

## Scope disclaimer (paste at end of customer pack)

> This pack addresses **agent tool-call / MCP control-plane** questions.  
> Corporate SSO estate, HR, physical security, and organization-wide SOC2 evidence remain owned by `{COMPANY}` security program.
