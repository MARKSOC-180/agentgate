"""
metering.py —— 用量计量与计费(把控制平面变成「按调用量收过路费」的网关)。

商业模式升维：不再卖一次性 license，而是对「每一次穿过控制平面的 agent 调用」计费。

两种计费视角：
  - usage_report(audit_path, ...)  事后从**不可篡改的哈希链审计**派生账单
                                   ——可验证、不可抵赖(invoice you can't dispute)。
  - Meter(...)                     运行时**实时**计量：网关边跑边累计，随时 snapshot()
                                   出当前账单，并把用量事件落到独立 usage 日志。

  - Pricing                 定价模型(单价 + 免费额度 + 计费口径)
  - usage_report(...)       事后从审计链派生账单
  - Meter                   长驻进程(如 MCP 代理)中的实时计量器
  - billing_csv(...)        导出可对账/开票的 CSV

纯标准库。
"""

from __future__ import annotations

import csv
import json
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass

from .audit import AuditLog


@dataclass
class Pricing:
    """
    计费模型(默认对「所有穿过网关的调用」计费——放行与拦截都算一次处理)。

        Pricing(price_per_call=0.002, included_calls=1000)   # 每调用 $0.002，前 1000 免费
    """
    price_per_call: float = 0.0
    included_calls: int = 0                 # 免费额度(按分组 key，例如每个 principal)
    currency: str = "USD"
    billable_decisions: tuple = ("allow", "block")  # 计费口径，默认两者都计

    @classmethod
    def from_dict(cls, data: dict) -> "Pricing":
        data = data or {}
        return cls(
            price_per_call=float(data.get("price_per_call", 0.0)),
            included_calls=int(data.get("included_calls", 0)),
            currency=data.get("currency", "USD"),
            billable_decisions=tuple(data.get("billable_decisions", ("allow", "block"))),
        )


def _empty_group() -> dict:
    return {"calls": 0, "allow": 0, "block": 0, "redactions": 0, "billable": 0}


def _accumulate(group: dict, decision: str, redactions: int, pricing: Pricing) -> None:
    group["calls"] += 1
    if decision in ("allow", "block"):
        group[decision] += 1
    group["redactions"] += int(redactions or 0)
    if decision in pricing.billable_decisions:
        group["billable"] += 1


def _price(groups: dict, pricing: Pricing, by: str) -> dict:
    """把聚合后的 groups 套上定价，得到带金额的账单 dict。"""
    rows = {}
    grand = {"calls": 0, "allow": 0, "block": 0, "redactions": 0,
             "billable": 0, "amount": 0.0}
    for key, g in groups.items():
        billable_after_free = max(0, g["billable"] - pricing.included_calls)
        amount = round(billable_after_free * pricing.price_per_call, 4)
        rows[key] = {**g, "billable_charged": billable_after_free, "amount": amount}
        for k in ("calls", "allow", "block", "redactions", "billable"):
            grand[k] += g[k]
        grand["amount"] = round(grand["amount"] + amount, 4)
    return {
        "by": by,
        "rows": rows,
        "totals": grand,
        "pricing": {"price_per_call": pricing.price_per_call,
                    "included_calls": pricing.included_calls,
                    "currency": pricing.currency},
    }


def usage_report(audit_path: str = "agentgate_audit.ndjson",
                 pricing: Pricing = None, by: str = "principal") -> dict:
    """事后从审计链派生用量与账单。by 可为 'principal' 或 'tool'。"""
    pricing = pricing or Pricing()
    records = AuditLog(audit_path).load()

    groups = defaultdict(_empty_group)
    for r in records:
        key = r.get(by) or ("anon" if by == "principal" else "—")
        red = sum(int(n) for n in (r.get("redaction_hits") or {}).values()
                  if str(n).lstrip("-").isdigit())
        _accumulate(groups[key], r.get("decision", ""), red, pricing)

    report = _price(groups, pricing, by)
    report["verifiable"] = True            # 源自哈希链，可验证不可抵赖
    report["audit_path"] = audit_path
    return report


class Meter:
    """
    运行时实时计量器：长驻网关(如 MCP 代理)边跑边累计，随时出当前账单。

        meter = Meter(Pricing(price_per_call=0.002), usage_path="usage.ndjson")
        meter.record("alice", "read", "allow", redactions=1)
        meter.snapshot()    # -> 当前实时账单(按 principal)
    """

    def __init__(self, pricing: Pricing = None, usage_path: str = None):
        self.pricing = pricing or Pricing()
        self.usage_path = usage_path
        self._lock = threading.Lock()
        self._groups = defaultdict(_empty_group)
        if usage_path:
            os.makedirs(os.path.dirname(os.path.abspath(usage_path)), exist_ok=True)

    def record(self, principal, tool, decision, redactions: int = 0) -> dict:
        key = principal or "anon"
        event = {"ts": time.time(), "principal": key, "tool": tool,
                 "decision": decision, "redactions": int(redactions or 0)}
        with self._lock:
            _accumulate(self._groups[key], decision, redactions, self.pricing)
            if self.usage_path:
                with open(self.usage_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
        return event

    def snapshot(self) -> dict:
        """当前实时账单。注意：实时计量为运营便利，非不可篡改凭证。"""
        with self._lock:
            report = _price(dict(self._groups), self.pricing, "principal")
        report["verifiable"] = False
        report["live"] = True
        return report

    @classmethod
    def from_dict(cls, data: dict) -> "Meter":
        data = data or {}
        return cls(pricing=Pricing.from_dict(data.get("pricing", data)),
                   usage_path=data.get("usage_path"))


def billing_csv(report: dict, out_path: str) -> str:
    """把用量报表导出为可开票/对账的 CSV。"""
    by = report["by"]
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([by, "calls", "allowed", "blocked", "redactions",
                    "billable", "charged", f"amount_{report['pricing']['currency']}"])
        for key, r in sorted(report["rows"].items(), key=lambda kv: -kv[1]["amount"]):
            w.writerow([key, r["calls"], r["allow"], r["block"], r["redactions"],
                        r["billable"], r["billable_charged"], r["amount"]])
        t = report["totals"]
        w.writerow(["TOTAL", t["calls"], t["allow"], t["block"], t["redactions"],
                    t["billable"], "", t["amount"]])
    return out_path
