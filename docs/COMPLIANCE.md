# Compliance mapping

AgentGate exports map to common frameworks via `agentgate export`:

| Output | Use |
|---|---|
| `compliance_report.md` | Human audit pack |
| `audit_export.csv` | Excel / GRC import |
| `audit_export.json` | API / data lake |
| `audit_export.cef` | Splunk / QRadar / Sentinel |

## Framework coverage (v0.2)

| Control | AgentGate module | SOC2 | GDPR | EU AI Act | HIPAA |
|---|---|---|---|---|---|
| Access control | policy.py, identity.py | CC6.1 | Art.32 | Art.14 | §164.312(a)(1) |
| Transmission / minimization | redact.py | CC6.7 | Art.32 | — | §164.312(e) |
| Anomaly / abuse | safety.py, limits.py | CC7.2 | — | Art.15 | — |
| Change authorization | approvals.py | CC6.3 | — | Art.14 | §164.308(a)(3) |
| Audit controls | audit.py, anchoring.py | CC7.3 | Art.30 | Art.12 | §164.312(b) |
| Emergency stop | policy killswitch | — | — | Art.14 | §164.308(a)(6) |

> HIPAA mapping is **assistive**, not a certification. Engage qualified assessors for BAAs and full HIPAA programs.

JSON Schema: [schema/audit-record.schema.json](../schema/audit-record.schema.json)
