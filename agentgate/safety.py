"""
safety.py —— 危险动作检测。

即便一个工具被策略放行了，它的「参数」里也可能藏着危险意图：
无 WHERE 的批量删除、rm -rf、超大额转账/退款、命令注入、SSRF……
这一层扫描调用参数，给出风险标记，可与策略联动(高危直接拦)。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class SafetyFinding:
    severity: str      # critical / high / warning
    title: str
    detail: str


# (severity, title, 正则, 说明)
_RULES = [
    ("critical", "Unconditional bulk delete",
     re.compile(r"\b(DELETE\s+FROM|TRUNCATE\s+TABLE|DROP\s+(TABLE|DATABASE))\b(?![\s\S]*\bWHERE\b)", re.I),
     "SQL delete/truncate/drop with no WHERE clause; could wipe an entire table."),
    ("critical", "Dangerous shell operation",
     re.compile(r"(rm\s+-rf\s+/|mkfs|:\(\)\s*\{|dd\s+if=)", re.I),
     "Detected a shell command capable of destroying the system."),
    ("high", "Command-injection indicators",
     re.compile(r"(;\s*(rm|curl|wget|bash|sh)\b|\$\(.*\)|`.*`|\|\s*sh\b)"),
     "Argument contains shell fragments that could be concatenated and executed."),
    ("high", "Possible SSRF / internal probing",
     re.compile(r"https?://(127\.0\.0\.1|localhost|169\.254\.169\.254|10\.\d|192\.168\.)", re.I),
     "Accesses internal/loopback/cloud-metadata addresses; possible SSRF."),
    ("high", "Oversized money operation",
     re.compile(r"\"?amount\"?\s*[:=]\s*\"?(\d{5,})", re.I),
     "Unusually large amount (>=10000); financial operations should be reviewed."),
    ("warning", "Wildcard / bulk operation",
     re.compile(r"(WHERE\s+1\s*=\s*1|all\s*=\s*true|\"\*\"|'\*')", re.I),
     "Matches 'all' semantics; blast radius may be larger than intended."),
]


def scan_safety(tool: str, inputs) -> list:
    """扫描某次工具调用的参数，返回风险发现列表。"""
    text = _stringify(inputs)
    findings: list = []
    for sev, title, pat, detail in _RULES:
        if pat.search(text):
            findings.append(SafetyFinding(sev, title, detail))
    return findings


def max_severity(findings: list) -> str | None:
    order = {"critical": 0, "high": 1, "warning": 2}
    if not findings:
        return None
    return sorted(findings, key=lambda f: order.get(f.severity, 9))[0].severity


def _stringify(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(f"{k}={_stringify(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return " ".join(_stringify(v) for v in value)
    return str(value)
