"""
gateway.py —— 核心网关 / 控制平面。

每一次工具调用都走这条流水线：
    拦截 → 策略判定 → 安全扫描 → (放行则)执行 → 输入/输出脱敏 → 审计上链 → 结构化追踪

一行接入任意工具(框架无关)：
    gate = Gateway(policy=..., audit_path=..., trace_path=...)
    safe_tool = gate.wrap("issue_refund", issue_refund, destructive=True)
    safe_tool({"order": "o-1", "amount": 50}, principal="user-1", authorized=True)
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .policy import Policy, Decision
from .redact import redact
from .safety import scan_safety, max_severity
from .audit import AuditLog, digest
from .approvals import ApprovalStore, APPROVED, DENIED
from .identity import coerce_identity, principal_id


class Blocked(Exception):
    """当一次工具调用被控制平面拦截时抛出。"""
    def __init__(self, tool: str, reasons: list):
        self.tool = tool
        self.reasons = reasons
        super().__init__(f"AgentGate blocked tool `{tool}`: {'; '.join(reasons)}")


@dataclass
class CallResult:
    tool: str
    decision: str                 # allow / block
    reasons: list = field(default_factory=list)
    output: object = None
    redaction_hits: dict = field(default_factory=dict)
    safety: list = field(default_factory=list)
    duration_ms: float = 0.0


class Gateway:
    def __init__(self, policy: Optional[Policy] = None,
                 audit_path: str = "agentgate_audit.ndjson",
                 trace_path: str = "agentgate_trace.ndjson",
                 limits=None, approvals=None, alerts=None,
                 anchor=None, anchor_every: int = 0,
                 meter=None, intel=None):
        self.policy = policy or Policy()
        self.audit = AuditLog(audit_path)
        self.trace_path = trace_path
        self.limits = limits          # 可选：Limiter(配额/限流)
        self.alerts = alerts          # 可选：Alerter(实时告警)
        self.anchor = anchor          # 可选：Anchor(审计链外部锚定)
        self.anchor_every = anchor_every  # >0 时每 N 条审计记录自动锚一次
        self.meter = meter            # 可选：Meter(实时计量/计费)
        self.intel = intel            # 可选：ThreatIntel(威胁情报数据飞轮)
        self._appended = 0
        # 需审批工具非空时，默认挂一个本地审批库
        if approvals is None and getattr(self.policy, "require_approval_tools", None):
            approvals = ApprovalStore()
        self.approvals = approvals
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(trace_path)), exist_ok=True)

    def anchor_now(self) -> Optional[dict]:
        """立即对审计链当前状态打一个外部锚点。"""
        if self.anchor is not None:
            return self.anchor.anchor(self.audit)
        return None

    # ---- 主入口 ----
    def call(self, tool: str, inputs, handler: Optional[Callable] = None,
             principal=None, authorized: Optional[bool] = None,
             destructive: bool = False, raise_on_block: bool = False,
             approval_id: Optional[str] = None, cost: float = 0.0) -> CallResult:
        t0 = time.time()

        # principal 可为字符串(向后兼容)或 Identity/Principal(身份+委托上下文)
        identity = coerce_identity(principal)
        pid = principal_id(principal)

        # 执行前：安全扫描 + 策略 + 审批 + 限流 + 输入脱敏
        decision, safety, red_inputs, hits, limits_record = self.precheck(
            tool, inputs, principal=pid, authorized=authorized,
            destructive=destructive, approval_id=approval_id, cost=cost,
            identity=identity)

        output = None
        if decision.allowed and handler is not None:
            # 放行才执行真实工具
            output = handler(inputs)

        # 执行后：输出脱敏 + 审计上链 + 追踪 + 配额计数 + 告警
        result = self.finalize(tool, red_inputs, decision, safety, hits, output,
                               principal=pid, t0=t0, cost=cost, identity=identity,
                               limits_record=limits_record)

        if not decision.allowed and raise_on_block:
            raise Blocked(tool, decision.reasons)
        return result

    # ---- 执行前判定(可被 MCP 代理等外部执行路径复用)----
    def precheck(self, tool: str, inputs, principal=None,
                 authorized: Optional[bool] = None, destructive: bool = False,
                 approval_id: Optional[str] = None, cost: float = 0.0,
                 identity=None):
        """只做「执行前」的判定，不执行工具。

        返回 (decision, safety, red_inputs, hits)。
        判定顺序：策略(含基于身份/委托的 scope 授权) → critical 安全升级 → 人在环审批 → 配额/限流。
        """
        if destructive:
            self.policy.destructive_tools = set(self.policy.destructive_tools) | {tool}

        # 允许直接给 precheck 传 Identity/Principal(例如 MCP 代理路径)
        if identity is None:
            identity = coerce_identity(principal)
        if not isinstance(principal, str) and principal is not None:
            principal = principal_id(principal)

        safety = scan_safety(tool, inputs)
        sev = max_severity(safety)

        decision: Decision = self.policy.evaluate(tool, inputs, principal, authorized,
                                                  identity=identity)
        # critical 级安全发现直接升级为拦截
        if sev == "critical" and decision.allowed:
            decision = Decision("block", [f"Critical safety risk detected: {safety[0].title}"])

        # 人在环审批：被标记的工具需人工点头。
        # 审批是「人类监督」闸门，对「仅因破坏性被拦」的操作行使放行权——
        # 即破坏性操作不直接拒绝，而是停下来等人审批(EU AI Act Art.14)。
        appr_tools = getattr(self.policy, "require_approval_tools", set())
        if tool in appr_tools and (decision.allowed or self._is_destructive_block(decision)):
            decision = self._check_approval(tool, principal, approval_id, inputs)

        # 配额 / 限流(策略放行后再加一道闸)
        limits_record = None
        if decision.allowed and self.limits is not None:
            reason = self.limits.check(tool, principal, cost=cost)
            if reason:
                decision = Decision("block", [reason])
            else:
                limits_record = {"checked": True, "cost": cost}

        red_inputs, hits = redact(inputs)
        return decision, safety, red_inputs, hits, limits_record

    @staticmethod
    def _approval_from_decision(decision: Decision) -> Optional[dict]:
        """从 decision.reasons 提取审批上下文(若有)。"""
        import re
        for r in decision.reasons or []:
            m = re.search(r"approval_id=([^,\)\s]+)", r)
            if m:
                aid = m.group(1)
                if "Approved by human" in r:
                    st = "approved"
                elif "denied by human" in r.lower():
                    st = "denied"
                else:
                    st = "pending"
                return {"id": aid, "status": st}
        return None

    @staticmethod
    def _is_destructive_block(decision: Decision) -> bool:
        """判断一次拦截是否「仅因破坏性闸门」——这种情况可由人在环审批接管。"""
        return (not decision.allowed and len(decision.reasons) == 1
                and "destructive operation" in decision.reasons[0])

    def _check_approval(self, tool, principal, approval_id, inputs) -> Decision:
        store = self.approvals
        if store is None:
            self.approvals = store = ApprovalStore()
        if approval_id:
            st = store.status(approval_id)
            if st == APPROVED:
                return Decision("allow", [f"Approved by human (approval_id={approval_id})"])
            if st == DENIED:
                return Decision("block", [f"Action denied by human (approval_id={approval_id})"])
            # 未知 id 视为无效，走重新申请
        aid = store.request(tool, principal, reason=f"{tool} requires human approval",
                            input_digest=digest(redact(inputs)[0]))
        return Decision("block", [f"Tool `{tool}` requires human approval; request logged "
                                  f"(approval_id={aid}, approve with "
                                  f"`agentgate approvals approve {aid}`)"])

    # ---- 执行后收尾(输出脱敏 + 审计上链 + 追踪 + 配额 + 告警)----
    def finalize(self, tool: str, red_inputs, decision: Decision, safety: list,
                 hits: dict, output, principal=None,
                 t0: Optional[float] = None, cost: float = 0.0,
                 identity=None, limits_record: dict = None) -> CallResult:
        """对(已执行的)输出做脱敏、写审计链与追踪，返回 CallResult。"""
        if output is not None:
            output, hits = redact(output, hits)

        if identity is None:
            identity = coerce_identity(principal)
        if not isinstance(principal, str) and principal is not None:
            principal = principal_id(principal)
        identity_record = identity.to_record() if identity is not None else None
        approval_record = self._approval_from_decision(decision)

        duration_ms = (time.time() - (t0 or time.time())) * 1000.0

        # 放行的调用计入配额/限流窗口
        if decision.allowed and self.limits is not None:
            self.limits.commit(tool, principal, cost=cost)

        # 审计上链(只存摘要哈希，不存明文)。identity 为可选扩展字段(§2.10)，
        # 不在 §3 REQUIRED_FIELDS 内：无身份上下文时记录与旧版逐字节一致。
        self.audit.append(
            tool=tool, principal=principal, decision=decision.action,
            reasons=decision.reasons, redaction_hits=hits, safety=safety,
            input_digest=digest(red_inputs), output_digest=digest(output),
            duration_ms=duration_ms, identity=identity_record,
            limits=limits_record, approval=approval_record,
        )
        # 外部锚定：每 N 条自动打一个锚点(让历史无法被神不知鬼不觉重写)
        self._appended += 1
        if self.anchor is not None and self.anchor_every > 0 \
                and self._appended % self.anchor_every == 0:
            try:
                self.anchor.anchor(self.audit)
            except Exception:
                pass
        # 结构化追踪(脱敏后的输入输出，可回放)
        span = {
            "ts": time.time(), "tool": tool, "principal": principal,
            "decision": decision.action, "reasons": decision.reasons,
            "redaction_hits": hits, "safety": [f"{s.severity}:{s.title}" for s in safety],
            "inputs": red_inputs, "output": output, "duration_ms": round(duration_ms, 3),
        }
        if identity_record is not None:
            span["identity"] = identity_record
        self._trace(span)

        # 实时告警(被拦截 或 命中阈值严重度)
        if self.alerts is not None:
            sev = max_severity(safety)
            if self.alerts.should_fire(decision.action, sev):
                self.alerts.notify({
                    "ts": time.time(), "tool": tool, "principal": principal,
                    "decision": decision.action, "reasons": decision.reasons,
                    "severity": sev,
                    "safety": [f"{s.severity}:{s.title}" for s in safety],
                })

        # 实时计量/计费(每次穿过网关的调用都计一笔)
        if self.meter is not None:
            try:
                self.meter.record(principal, tool, decision.action,
                                  redactions=sum(hits.values()) if hits else 0)
            except Exception:
                pass

        # 威胁情报埋点(仅拦截/高危才记，且只存隐私安全指纹)
        if self.intel is not None:
            try:
                self.intel.record(tool, decision.action, decision.reasons,
                                  safety, principal=principal, inputs=red_inputs)
            except Exception:
                pass

        return CallResult(tool=tool, decision=decision.action, reasons=decision.reasons,
                          output=output, redaction_hits=hits, safety=safety,
                          duration_ms=duration_ms)

    # ---- 一行接入：把任意工具函数包成「受控工具」----
    def wrap(self, tool: str, handler: Callable, destructive: bool = False) -> Callable:
        def controlled(inputs, principal=None, authorized=None):
            return self.call(tool, inputs, handler=handler, principal=principal,
                             authorized=authorized, destructive=destructive)
        return controlled

    def kill(self):
        """急停：开启全局 kill-switch。"""
        self.policy.killswitch = True

    def resume(self):
        self.policy.killswitch = False

    def _trace(self, span: dict):
        with self._lock:
            with open(self.trace_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(span, ensure_ascii=False, default=str) + "\n")
