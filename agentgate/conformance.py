"""
conformance.py —— MCP-SP 一致性自检工具(标准的「病毒载体」)。

为什么这是标准扩散速度的极限加速器：
标准要成为「价值的必经节点」，唯一靠**采纳**。而采纳速度的瓶颈，是「别人实现它 +
证明自己合规」的成本。把这个成本压到**一条命令**，并给出一个可贴进 README 的**徽章**
(就像当年 `build passing` 徽章病毒式铺满 GitHub)，采纳就会自我复制。

任何 MCP host / gateway / server 实现者，只要按 SPEC §3 产出审计日志，就能：

    agentgate conformance their_audit.ndjson --anchors their_anchors.ndjson

得到「MCP-SP Level N conformant」判定 + 一段徽章 Markdown，贴进自己仓库。
每一个贴徽章的人，都在替这个标准做分发。

判定基于**证据**(审计日志本身能证明的)，对无法仅凭日志证明的能力(自托管/局部性)
允许通过 declared capabilities 声明——输出会如实区分「证据」与「声明」。

纯标准库。
"""

from __future__ import annotations

import hashlib
import json
import os
from urllib.parse import quote

# MCP-SP §3：审计记录必需字段(Level 1 Baseline 的硬门槛)
REQUIRED_FIELDS = ["ts", "tool", "principal", "decision", "reasons",
                   "redaction_hits", "input_sha256", "output_sha256",
                   "prev_hash", "this_hash"]

_BADGE_COLOR = {0: "red", 1: "yellow", 2: "blue", 3: "brightgreen"}


def _canonical(body: dict) -> str:
    """SPEC §3 的 canonical(body)：键名排序的 JSON(对齐参考实现的序列化)。"""
    return json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)


def _record_hash(prev_hash: str, body: dict) -> str:
    return hashlib.sha256((prev_hash + "|" + _canonical(body)).encode("utf-8")).hexdigest()


def _load(path: str) -> list:
    out = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def check_conformance(audit_path: str, anchors_path: str = None,
                      capabilities: dict = None) -> dict:
    """
    检验一份审计日志是否符合 MCP-SP，并判定其一致性等级(0–3)。

    返回 dict：{level, passed[], failed[], evidence{}, declared{}, badge}
    """
    capabilities = capabilities or {}
    records = _load(audit_path)
    passed, failed = [], []

    # —— Level 1 / Baseline：§2.1 策略 + §2.2 脱敏 + §2.6 不可篡改审计 ——
    if not records:
        failed.append("Audit log is empty — cannot demonstrate any control")
        return _result(0, passed, failed, capabilities, audit_path)

    # 1a. 记录 schema 完整
    schema_ok = True
    for i, r in enumerate(records, 1):
        missing = [f for f in REQUIRED_FIELDS if f not in r]
        if missing:
            schema_ok = False
            failed.append(f"§3 record #{i} missing required field(s): {', '.join(missing)}")
            break
    if schema_ok:
        passed.append("§3 Audit-record schema: all required fields present")

    # 1b. decision 取值合法
    decisions_ok = all(r.get("decision") in ("allow", "block") for r in records)
    (passed if decisions_ok else failed).append(
        "§2.1 Policy: every record carries a decision of allow|block"
        if decisions_ok else "§2.1 Policy: found a record whose decision is not allow|block")

    # 1c. 脱敏被记录(每条都带 redaction_hits 映射)
    redaction_ok = all(isinstance(r.get("redaction_hits"), dict) for r in records)
    (passed if redaction_ok else failed).append(
        "§2.2 Redaction: every record records redaction hits"
        if redaction_ok else "§2.2 Redaction: a record is missing a redaction_hits map")

    # 1d. 哈希链完整(任何删改插都会被发现)
    chain_ok, chain_msg = _verify_chain(records)
    (passed if chain_ok else failed).append("§2.6 Tamper-evident audit: " + chain_msg)

    # 1e. §2.10 身份/委托上下文(可选)若出现，必须自洽
    identity_ok, identity_msg = _verify_identity(records)
    (passed if identity_ok else failed).append("§2.10 Identity & delegation: " + identity_msg)

    lim_ok, lim_msg = _verify_limits_approval(records)
    (passed if lim_ok else failed).append("§2.4/§2.5 Limits & approval: " + lim_msg)

    level1 = schema_ok and decisions_ok and redaction_ok and chain_ok and identity_ok and lim_ok

    # —— Level 2 / Governed：§2.3 安全 + §2.4 限流 + §2.5 审批 ——
    # 日志能直接证明的是 §2.3：每条都带 safety 字段。限流/审批属能力声明。
    safety_ok = all("safety" in r for r in records)
    (passed if safety_ok else failed).append(
        "§2.3 Safety: every record carries a safety findings field"
        if safety_ok else "§2.3 Safety: a record is missing the safety field")
    level2 = level1 and safety_ok

    # —— Level 3 / Assured：§2.7 外部锚定 + §2.9 局部性 ——
    anchored_ok = False
    if anchors_path:
        anchored_ok, a_msg = _verify_anchors(audit_path, anchors_path)
        (passed if anchored_ok else failed).append("§2.7 External anchoring: " + a_msg)
    else:
        failed.append("§2.7 External anchoring: no anchors file provided (required for Level 3)")
    level3 = level2 and anchored_ok

    level = 3 if level3 else 2 if level2 else 1 if level1 else 0
    return _result(level, passed, failed, capabilities, audit_path)


def _verify_identity(records: list) -> tuple:
    """§2.10：审计记录里若带 identity，必须结构自洽(委托链与 actor/subject 一致、
    grants 为有序的 scope 字符串列表)。无 identity 的日志不受影响(可选扩展)。"""
    seen = 0
    for i, r in enumerate(records, 1):
        ident = r.get("identity")
        if ident is None:
            continue
        seen += 1
        if not isinstance(ident, dict):
            return False, f"record #{i}: identity must be an object"
        chain = ident.get("delegation")
        if not isinstance(chain, list) or not chain:
            return False, f"record #{i}: identity.delegation must be a non-empty list"
        if ident.get("actor") != chain[0]:
            return False, f"record #{i}: identity.actor must equal delegation[0]"
        if ident.get("subject") != chain[-1]:
            return False, f"record #{i}: identity.subject must equal delegation[-1]"
        granted = ident.get("granted")
        if not isinstance(granted, list) or any(not isinstance(g, str) for g in granted):
            return False, f"record #{i}: identity.granted must be a list of scope strings"
        if list(granted) != sorted(granted):
            return False, f"record #{i}: identity.granted must be sorted"
    if seen == 0:
        return True, "no identity context present (optional §2.10)"
    return True, f"{seen} record(s) carry a consistent identity/delegation context"


def _verify_limits_approval(records: list) -> tuple:
    """§2.4/§2.5：limits/approval 可选扩展字段若出现，必须结构自洽。"""
    lim_seen = appr_seen = 0
    for i, r in enumerate(records, 1):
        lim = r.get("limits")
        if lim is not None:
            lim_seen += 1
            if not isinstance(lim, dict) or "checked" not in lim:
                return False, f"record #{i}: limits must include checked"
        appr = r.get("approval")
        if appr is not None:
            appr_seen += 1
            if not isinstance(appr, dict) or not isinstance(appr.get("id"), str):
                return False, f"record #{i}: approval.id required"
            if appr.get("status") not in ("pending", "approved", "denied"):
                return False, f"record #{i}: approval.status invalid"
    if not lim_seen and not appr_seen:
        return True, "no limits/approval extensions (optional §2.4/§2.5)"
    parts = []
    if lim_seen:
        parts.append(f"{lim_seen} limits")
    if appr_seen:
        parts.append(f"{appr_seen} approval")
    return True, f"{', '.join(parts)} well-formed"


def _verify_chain(records: list) -> tuple:
    prev = "GENESIS"
    for i, rec in enumerate(records, 1):
        claimed = rec.get("this_hash")
        body = {k: v for k, v in rec.items() if k != "this_hash"}
        if body.get("prev_hash") != prev:
            return False, f"record #{i}: prev_hash breaks the chain (deleted/inserted?)"
        if _record_hash(prev, body) != claimed:
            return False, f"record #{i}: hash mismatch (tampered, or non-canonical hashing?)"
        prev = claimed
    return True, f"chain intact, {len(records)} records, no tampering"


def _verify_anchors(audit_path: str, anchors_path: str) -> tuple:
    try:
        from .audit import AuditLog
        from .anchoring import Anchor
        # Level 3(Assured)必须真有锚点：空锚点文件不能凭「空集为真」蒙混过关
        if not _load(anchors_path):
            return False, "anchors file is empty; Level 3 requires at least one verified anchor"
        return Anchor(anchors_path).verify(AuditLog(audit_path))
    except Exception as e:                       # 容错：锚定校验失败不应使工具崩溃
        return False, f"anchor verification error: {e}"


def badge_markdown(level: int) -> str:
    """生成可贴进 README 的 shields.io 徽章 Markdown。"""
    color = _BADGE_COLOR.get(level, "red")
    label = quote(f"Level {level}") if level else quote("not conformant")
    url = f"https://img.shields.io/badge/MCP--SP-{label}-{color}"
    return f"[![MCP-SP]({url})](https://github.com/agentgate/agentgate/blob/main/SPEC.md)"


def _result(level: int, passed: list, failed: list,
            capabilities: dict, audit_path: str) -> dict:
    return {
        "spec": "MCP-SP/0.2",
        "level": level,
        "level_name": {0: "not conformant", 1: "Baseline",
                       2: "Governed", 3: "Assured"}[level],
        "passed": passed,
        "failed": failed,
        "declared": {                            # 仅凭日志无法证明的，作为声明如实标注
            "selfHosted": bool(capabilities.get("selfHosted", False)),
        },
        "badge": badge_markdown(level),
        "audit_path": audit_path,
    }
