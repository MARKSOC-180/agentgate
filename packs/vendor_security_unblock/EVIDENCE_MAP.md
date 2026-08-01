# Evidence Map — which file answers which fear

| Reviewer fear | Attach first | Backup |
|---------------|--------------|--------|
| “No proof of who called what” | `compliance_export/audit_export.csv` | `agentgate_report.html` |
| “Logs can be edited” | `README_DELIVERY.txt` (chain PASS) | anchors + Level 3 JSON |
| “Data leaves to SaaS” | Deployment note in README + local paths | config (redacted) |
| “No human oversight” | Audit rows with `approval` | policy gated tool list |
| “Can’t import to our GRC” | `audit_export.json` / `.cef` | `.md` narrative |
| “Is this a real standard?” | `mcp_sp_conformance.json` | `SPEC.md` link |
| “Secrets in prompts” | Redaction samples in report | redact config excerpt |

## Packaging order (make reviewers feel finished)

1. `README_DELIVERY.txt` — green PASS at top  
2. `vendor_security_unblock/QUESTION_BANK.md` (customer-edited)  
3. `agentgate_report.html`  
4. `mcp_sp_conformance.json`  
5. `compliance_export/`  
6. This map
