"""
compliance.py —— 合规导出(把审计链导成审计师能直接收的材料)。

买家(尤其企业)真正卡的第三件事：要能向审计师 / 监管「交差」。
本模块把哈希链审计日志导出为一个可移交的合规包：

  - compliance_report.md  —— 人类可读的合规报告：时间范围、总量、拦截/脱敏/安全
                              发现统计、哈希链校验结论、控制项到 SOC2 / EU AI Act 的映射
  - audit_export.csv      —— 全量审计记录(每行一条)，可导入 Excel / GRC 系统

零外部依赖(csv 为标准库)。导出只读审计文件，不改动原链。
"""

from __future__ import annotations

import csv
import json
import os
import time
from collections import Counter
from datetime import datetime, timezone

from .audit import AuditLog


def _cef_escape(val) -> str:
    s = str(val).replace("\\", "\\\\").replace("=", "\\=")
    return s.replace("\n", " ").replace("\r", " ")


# 控制项映射：把 AgentGate 的能力对到主流合规框架的条款，方便审计师对账。
_CONTROL_MAP = [
    ("Policy & authorization gate (policy.py)", "SOC2 CC6.1 logical access · EU AI Act Art.14 human oversight"),
    ("Secret/PII two-way redaction (redact.py)", "SOC2 CC6.7 transmission protection · GDPR Art.32 data minimization"),
    ("Dangerous-action detection (safety.py)", "SOC2 CC7.2 anomaly detection · EU AI Act Art.15 robustness"),
    ("Rate-limit & budget caps (limits.py)", "SOC2 CC7.2 anomaly/abuse control · EU AI Act Art.15 robustness"),
    ("Human-in-the-loop approval (approvals.py)", "SOC2 CC6.3 change authorization · EU AI Act Art.14 human oversight"),
    ("Hash-chained tamper-evident audit (audit.py)", "SOC2 CC7.3 / CC4.1 · HIPAA §164.312(b) audit · EU AI Act Art.12"),
    ("Identity & delegation attenuation (identity.py)", "SOC2 CC6.1 · HIPAA §164.312(a)(1) access · EU AI Act Art.14"),
    ("External anchoring (anchoring.py)", "SOC2 CC4.1 independent evidence · EU AI Act Art.12 non-repudiation"),
    ("Global kill-switch (policy.py)", "EU AI Act Art.14 immediate human intervention/stop"),
]


def _iso(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def export_compliance(audit_path: str = "agentgate_audit.ndjson",
                      out_dir: str = "compliance_export") -> dict:
    """读取审计链，生成合规包。返回包含输出路径与统计摘要的 dict。"""
    os.makedirs(out_dir, exist_ok=True)
    log = AuditLog(audit_path)
    records = log.load()
    chain_ok, chain_msg = log.verify()

    total = len(records)
    blocked = sum(1 for r in records if r.get("decision") == "block")
    allowed = total - blocked
    redaction_total = 0
    safety_counter: Counter = Counter()
    tool_counter: Counter = Counter()
    reason_counter: Counter = Counter()

    for r in records:
        for v in (r.get("redaction_hits") or {}).values():
            try:
                redaction_total += int(v)
            except Exception:
                pass
        for s in (r.get("safety") or []):
            safety_counter[s] += 1
        tool_counter[r.get("tool", "<unknown>")] += 1
        if r.get("decision") == "block":
            for reason in (r.get("reasons") or []):
                reason_counter[reason] += 1

    first_ts = records[0]["ts"] if records else None
    last_ts = records[-1]["ts"] if records else None

    # ---- CSV 全量导出 ----
    csv_path = os.path.join(out_dir, "audit_export.csv")
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["#", "timestamp_utc", "tool", "principal", "decision",
                    "reasons", "redaction_hits", "safety", "input_sha256",
                    "output_sha256", "duration_ms", "this_hash"])
        for i, r in enumerate(records, 1):
            w.writerow([
                i, _iso(r.get("ts")), r.get("tool"), r.get("principal"),
                r.get("decision"), " | ".join(r.get("reasons") or []),
                "; ".join(f"{k}:{v}" for k, v in (r.get("redaction_hits") or {}).items()),
                "; ".join(r.get("safety") or []),
                r.get("input_sha256"), r.get("output_sha256"),
                r.get("duration_ms"), r.get("this_hash"),
            ])

    # ---- Markdown 合规报告 ----
    md_path = os.path.join(out_dir, "compliance_report.md")
    verdict = "✅ PASS — audit chain intact, no tampering" if chain_ok else "❌ FAIL — tampering detected"
    lines = []
    lines.append("# AgentGate Compliance Report\n")
    lines.append(f"- Generated: {_iso(time.time())}")
    lines.append(f"- Audit file: `{audit_path}`")
    lines.append(f"- Coverage: {_iso(first_ts)} → {_iso(last_ts)}" if records else "- Coverage: (empty)")
    lines.append("")
    lines.append("## 1. Integrity verdict (hash-chain verification)\n")
    lines.append(f"**{verdict}**\n")
    lines.append(f"> {chain_msg}\n")
    lines.append("Hash chain: every record embeds the SHA-256 of the previous one, so any "
                 "edit/deletion/insertion breaks the chain and is located by `verify()`. "
                 "This is the technical basis for non-repudiation.\n")
    lines.append("## 2. Activity overview\n")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Total tool calls | {total} |")
    lines.append(f"| Allowed | {allowed} |")
    lines.append(f"| Blocked | {blocked} |")
    lines.append(f"| Redaction hits (secrets/PII) | {redaction_total} |")
    lines.append(f"| Records with safety findings | {sum(safety_counter.values())} |")
    lines.append("")
    if tool_counter:
        lines.append("### By tool\n")
        lines.append("| Tool | Calls |")
        lines.append("|---|---|")
        for tool, c in tool_counter.most_common():
            lines.append(f"| `{tool}` | {c} |")
        lines.append("")
    if reason_counter:
        lines.append("### Top block reasons\n")
        lines.append("| Reason | Count |")
        lines.append("|---|---|")
        for reason, c in reason_counter.most_common(10):
            lines.append(f"| {reason} | {c} |")
        lines.append("")
    if safety_counter:
        lines.append("### Safety findings\n")
        lines.append("| Finding | Count |")
        lines.append("|---|---|")
        for s, c in safety_counter.most_common():
            lines.append(f"| {s} | {c} |")
        lines.append("")
    lines.append("## 3. Controls mapping\n")
    lines.append("| AgentGate capability | Mapped clauses |")
    lines.append("|---|---|")
    for cap, mapping in _CONTROL_MAP:
        lines.append(f"| {cap} | {mapping} |")
    lines.append("")
    lines.append("## 4. Attachments\n")
    lines.append("- `audit_export.csv` — full audit records (one per line, including hashes).\n")
    lines.append("- `audit_export.json` — machine-readable full export for GRC/SIEM APIs.\n")
    lines.append("- `audit_export.cef` — CEF format for Splunk / QRadar / Sentinel.\n")
    lines.append("---\n")
    lines.append("> Generated by AgentGate entirely inside the customer's own environment. "
                 "No sensitive data leaves.\n")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # ---- JSON 全量导出(SIEM / GRC API) ----
    json_path = os.path.join(out_dir, "audit_export.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": time.time(),
            "audit_path": audit_path,
            "chain_ok": chain_ok,
            "chain_msg": chain_msg,
            "summary": {
                "total": total, "allowed": allowed, "blocked": blocked,
                "redaction_total": redaction_total,
            },
            "records": records,
        }, f, ensure_ascii=False, indent=2, default=str)

    # ---- CEF 导出(常见 SIEM 格式) ----
    cef_path = os.path.join(out_dir, "audit_export.cef")
    with open(cef_path, "w", encoding="utf-8") as f:
        for i, r in enumerate(records, 1):
            sev = 8 if r.get("decision") == "block" else 3
            ext = " ".join(
                f"{k}={_cef_escape(v)}" for k, v in [
                    ("tool", r.get("tool")),
                    ("principal", r.get("principal")),
                    ("decision", r.get("decision")),
                    ("msg", " | ".join(r.get("reasons") or [])),
                    ("hash", r.get("this_hash")),
                ] if v
            )
            f.write(
                f"CEF:0|AgentGate|ControlPlane|0.2|tool_call|"
                f"Agent tool call {r.get('decision')}|{sev}|{ext}\n"
            )

    return {
        "report_path": md_path,
        "csv_path": csv_path,
        "json_path": json_path,
        "cef_path": cef_path,
        "chain_ok": chain_ok,
        "chain_msg": chain_msg,
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "redaction_total": redaction_total,
    }


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "agentgate_audit.ndjson"
    info = export_compliance(path)
    print(f"合规包已生成：{info['report_path']} / {info['csv_path']}")
    print(f"链校验：{'PASS' if info['chain_ok'] else 'FAIL'} — {info['chain_msg']}")
