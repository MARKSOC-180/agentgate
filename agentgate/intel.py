"""
intel.py —— 威胁情报数据飞轮(L3 护城河的起点)。

每一次拦截 / 高危发现，都提取一条**隐私安全的攻击指纹**：只记录
「类别 / 严重度 / 工具 / 输入结构哈希」这类信号，**绝不存任何明文参数**。

为什么这是护城河：单点部署看到的攻击有限；但当许多部署把这些**匿名聚合指纹**
汇入一个共享情报源(opt-in)，规则库会「越多人用越准」——后来者无从追赶
(CrowdStrike for AI agents 的雏形)。

隐私红线：
  - 不存明文参数、不存密钥/PII(这些在 redact 阶段已被剥离)。
  - 只存：工具名、严重度、命中签名(safety 标题 / 策略原因类别)、
    输入「形状」的单向哈希(顶层键集合的 sha256 前 12 位)。
  - principal 仅在本地保留；export_feed() 产出的共享数据会剥离 principal。

  - ThreatIntel.record(...)   从一次判定提取指纹(仅 block 或 高危才记)
  - ThreatIntel.summarize()   本地聚合：top 攻击签名 / 按工具 / 按严重度
  - ThreatIntel.export_feed() 产出可贡献给共享情报网络的匿名聚合(opt-in)

纯标准库。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections import Counter

_RECORD_SEVERITIES = {"high", "critical"}   # 这些严重度即便放行也值得记录(near-miss)


def _shape(inputs) -> str:
    """对输入「形状」做单向哈希——只反映结构(顶层键集合)，不可逆、不含取值。"""
    try:
        if isinstance(inputs, dict):
            sig = "keys:" + ",".join(sorted(str(k) for k in inputs.keys()))
        elif isinstance(inputs, (list, tuple)):
            sig = f"seq:{len(inputs)}"
        else:
            sig = f"scalar:{type(inputs).__name__}"
    except Exception:
        sig = "unknown"
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()[:12]


def _policy_signature(reasons: list) -> str:
    """把一条策略拦截原因归一成稳定的「类别签名」(去掉具体工具名等可变部分)。"""
    text = " ".join(reasons or []).lower()
    if "kill-switch" in text:
        return "policy:kill-switch"
    if "deny list" in text:
        return "policy:deny-list"
    if "allow list" in text:
        return "policy:not-allowlisted"
    if "authorized" in text or "authorization" in text:
        return "policy:unauthorized"
    if "destructive" in text:
        return "policy:destructive"
    if "approval" in text:
        return "policy:awaiting-approval"
    if "budget" in text or "rate" in text or "limit" in text:
        return "policy:limit-exceeded"
    return "policy:other"


class ThreatIntel:
    def __init__(self, path: str = "agentgate_intel.ndjson"):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def record(self, tool: str, decision: str, reasons: list,
               safety: list, principal: str = None, inputs=None) -> dict:
        """从一次判定提取威胁指纹。仅当被拦截、或存在高危/严重安全发现时才记录。"""
        sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        top_sev = "none"
        for s in safety or []:
            if sev_rank.get(getattr(s, "severity", ""), 0) > sev_rank.get(top_sev, 0):
                top_sev = s.severity

        worth = (decision == "block") or (top_sev in _RECORD_SEVERITIES)
        if not worth:
            return {}

        indicators = []
        for s in safety or []:
            if sev_rank.get(getattr(s, "severity", ""), 0) >= sev_rank["high"]:
                indicators.append({"kind": "safety", "severity": s.severity,
                                   "signature": f"safety:{s.title}"})
        if decision == "block":
            indicators.append({"kind": "policy", "severity": "block",
                               "signature": _policy_signature(reasons)})

        event = {
            "ts": time.time(),
            "tool": tool,
            "principal": principal,        # 本地保留；export_feed 会剥离
            "decision": decision,
            "severity": top_sev,
            "shape": _shape(inputs),
            "indicators": indicators,
        }
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        return event

    def load(self) -> list:
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
        return out

    def summarize(self) -> dict:
        records = self.load()
        by_sig = Counter()
        by_tool = Counter()
        by_severity = Counter()
        blocks = 0
        for r in records:
            if r.get("decision") == "block":
                blocks += 1
            by_tool[r.get("tool", "—")] += 1
            by_severity[r.get("severity", "none")] += 1
            for ind in r.get("indicators", []):
                by_sig[ind.get("signature", "?")] += 1
        return {
            "events": len(records),
            "blocks": blocks,
            "top_threats": by_sig.most_common(10),
            "by_tool": dict(by_tool.most_common()),
            "by_severity": dict(by_severity),
        }

    def export_feed(self) -> dict:
        """产出可贡献给共享情报网络的**匿名**聚合(剥离 principal，仅签名/工具/严重度计数)。"""
        s = self.summarize()
        return {
            "schema": "agentgate-intel-feed/0.1",
            "generated_at": time.time(),
            "events": s["events"],
            "blocks": s["blocks"],
            "signatures": dict(s["top_threats"]),
            "by_tool": s["by_tool"],
            "by_severity": s["by_severity"],
        }
