"""
metrics.py —— 指标导出(Prometheus 文本格式)。

企业要把控制平面接进现有可观测体系(Prometheus + Grafana / 告警)。
本模块从审计链聚合出标准 Prometheus 文本，可被 scrape 或写成静态文件。

指标：
  agentgate_calls_total{decision="allow|block"}
  agentgate_tool_calls_total{tool="..."}
  agentgate_redactions_total
  agentgate_safety_findings_total{severity="critical|high|warning"}
  agentgate_audit_chain_ok            (1=完好, 0=被篡改)
  agentgate_audit_records             (记录总数)

零依赖：纯标准库读取 + 文本拼接。
"""

from __future__ import annotations

from collections import Counter

from .audit import AuditLog


def _sev(label: str) -> str:
    return label.split(":", 1)[0] if ":" in label else label


def collect(audit_path: str = "agentgate_audit.ndjson") -> dict:
    """从审计链聚合原始计数(便于测试与复用)。"""
    log = AuditLog(audit_path)
    records = log.load()
    chain_ok, _ = log.verify()

    decisions: Counter = Counter()
    tools: Counter = Counter()
    sev: Counter = Counter()
    redactions = 0
    for r in records:
        decisions[r.get("decision", "unknown")] += 1
        tools[r.get("tool", "unknown")] += 1
        for v in (r.get("redaction_hits") or {}).values():
            try:
                redactions += int(v)
            except Exception:
                pass
        for s in (r.get("safety") or []):
            sev[_sev(s)] += 1
    return {
        "records": len(records),
        "chain_ok": chain_ok,
        "decisions": dict(decisions),
        "tools": dict(tools),
        "severity": dict(sev),
        "redactions": redactions,
    }


def prometheus_text(audit_path: str = "agentgate_audit.ndjson") -> str:
    """生成 Prometheus 可抓取的文本。"""
    m = collect(audit_path)
    lines = []

    def metric(name, help_text, mtype="counter"):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")

    metric("agentgate_calls_total", "Total tool calls by decision")
    for decision, n in sorted(m["decisions"].items()):
        lines.append(f'agentgate_calls_total{{decision="{decision}"}} {n}')

    metric("agentgate_tool_calls_total", "Total tool calls by tool")
    for tool, n in sorted(m["tools"].items()):
        lines.append(f'agentgate_tool_calls_total{{tool="{tool}"}} {n}')

    metric("agentgate_redactions_total", "Total secret/PII redaction hits")
    lines.append(f"agentgate_redactions_total {m['redactions']}")

    metric("agentgate_safety_findings_total", "Safety findings by severity")
    for s, n in sorted(m["severity"].items()):
        lines.append(f'agentgate_safety_findings_total{{severity="{s}"}} {n}')

    metric("agentgate_audit_chain_ok", "Audit hash chain integrity (1=ok,0=tampered)", "gauge")
    lines.append(f"agentgate_audit_chain_ok {1 if m['chain_ok'] else 0}")

    metric("agentgate_audit_records", "Total audit records", "gauge")
    lines.append(f"agentgate_audit_records {m['records']}")

    return "\n".join(lines) + "\n"
