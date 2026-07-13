"""
redact.py —— 密钥 / PII 双向脱敏。

工具调用的「输入」和「输出」在被记录或流向下游之前，先在这里把敏感信息脱敏。
这样即便 agent 不小心读到了一个密钥或一堆客户 PII，它也不会原样流进日志、
流进下一个工具、流进 LLM 上下文。

纯正则、确定性、本地运行——不依赖任何外部服务。
"""

from __future__ import annotations

import re

# 密钥类(高危)
_SECRET_PATTERNS = [
    ("OpenAI key",    re.compile(r"sk-(proj-)?[A-Za-z0-9_-]{20,}")),
    ("Stripe secret", re.compile(r"(sk|rk)_live_[0-9A-Za-z]{20,}")),
    ("AWS key",       re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google key",    re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("GitHub token",  re.compile(r"(ghp_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{30,})")),
    ("Slack token",   re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("JWT/Supabase",  re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}")),
    ("Private key",   re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]

# PII 类
_PII_PATTERNS = [
    ("Email",       re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("Credit card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("US SSN",      re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("Phone",       re.compile(r"\b\+?\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}\b")),
    ("IPv4",        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

# 中国区 PII(身份证 / 手机号 / 统一社会信用代码)
_CN_PII_PATTERNS = [
    ("CN ID card",  re.compile(r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b")),
    ("CN mobile",   re.compile(r"\b1[3-9]\d{9}\b")),
    ("CN USCC",     re.compile(r"\b[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}\b")),
]


def _mask(label: str, match: str) -> str:
    """保留少量前后字符，中间打码，便于排查又不泄露。"""
    if len(match) <= 8:
        return f"[{label}:REDACTED]"
    return f"[{label}:{match[:3]}…{match[-2:]}]"


def _redact_text(text: str, found: dict) -> str:
    for label, pat in _SECRET_PATTERNS:
        def repl(m, lb=label):
            found[lb] = found.get(lb, 0) + 1
            return _mask(lb, m.group(0))
        text = pat.sub(repl, text)
    # 中国区 PII 先于通用 Phone，避免 11 位手机号被 Phone 规则抢走
    for label, pat in _CN_PII_PATTERNS:
        def repl(m, lb=label):
            found[lb] = found.get(lb, 0) + 1
            return _mask(lb, m.group(0))
        text = pat.sub(repl, text)
    for label, pat in _PII_PATTERNS:
        def repl(m, lb=label):
            found[lb] = found.get(lb, 0) + 1
            return _mask(lb, m.group(0))
        text = pat.sub(repl, text)
    return text


def redact(value, _found: dict | None = None):
    """
    递归脱敏任意结构(str / dict / list / 标量)。
    返回 (脱敏后的副本, 命中统计 dict)。原对象不被修改。
    """
    found = _found if _found is not None else {}

    if isinstance(value, str):
        return _redact_text(value, found), found
    if isinstance(value, dict):
        return {k: redact(v, found)[0] for k, v in value.items()}, found
    if isinstance(value, (list, tuple)):
        return [redact(v, found)[0] for v in value], found
    # 其它标量按字符串扫一遍(数字里也可能藏卡号)
    s = str(value)
    red = _redact_text(s, found)
    return (red if red != s else value), found
