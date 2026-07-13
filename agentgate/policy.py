"""
policy.py —— 策略引擎(治理层)。

在工具调用「执行之前」做决策：
  - 全局 kill-switch：一键叫停所有调用
  - 拒绝名单 / 允许名单：least-privilege，默认可收紧到白名单
  - 需授权工具：必须 principal 已授权(authorized=True)才放行
  - 破坏性工具：标记为高危，未显式批准则拦截

这一层正是 OTel GenAI 规范里缺失、却最关键的「谁、以什么权限、能做什么」。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Decision:
    """一次策略判定的结果。"""
    action: str               # allow / block
    reasons: list = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


@dataclass
class Policy:
    """
    一份可声明的策略。默认宽松(放行未知工具)，可逐步收紧到白名单。

        policy = Policy(
            allow_tools={"web_search", "read_db"},      # None 表示全部允许
            deny_tools={"shell_exec"},
            require_auth_tools={"issue_refund", "delete_records"},
            destructive_tools={"delete_records", "issue_refund", "drop_table"},
        )
    """
    allow_tools: Optional[set] = None      # None = 允许所有(未被 deny 的)
    deny_tools: set = field(default_factory=set)
    require_auth_tools: set = field(default_factory=set)
    require_approval_tools: set = field(default_factory=set)  # 需人在环审批
    destructive_tools: set = field(default_factory=set)
    tool_scopes: dict = field(default_factory=dict)  # 工具 -> 所需 scope 集合(基于身份/委托授权)
    allow_destructive: bool = False        # 是否放行破坏性操作(默认否)
    killswitch: bool = False               # 全局急停

    # ---- 从配置加载(让客户用 JSON 声明策略，无需改代码)----
    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        """从一个 dict 构造策略。未知键忽略，列表自动转 set。

        期望结构(全部可选)：
            {
              "allow_tools": ["web_search", "read_db"],   // 省略或 null = 允许所有
              "deny_tools": ["shell_exec"],
              "require_auth_tools": ["issue_refund"],
              "destructive_tools": ["delete_records"],
              "allow_destructive": false
            }
        """
        data = data or {}
        allow = data.get("allow_tools", None)
        scopes = data.get("tool_scopes", {}) or {}
        return cls(
            allow_tools=set(allow) if allow is not None else None,
            deny_tools=set(data.get("deny_tools", []) or []),
            require_auth_tools=set(data.get("require_auth_tools", []) or []),
            require_approval_tools=set(data.get("require_approval_tools", []) or []),
            destructive_tools=set(data.get("destructive_tools", []) or []),
            tool_scopes={t: set(s or []) for t, s in scopes.items()},
            allow_destructive=bool(data.get("allow_destructive", False)),
        )

    @classmethod
    def from_file(cls, path: str) -> "Policy":
        """从 JSON 文件加载策略。支持顶层就是策略，或嵌在 {"policy": {...}} 下。"""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and "policy" in data:
            data = data["policy"]
        return cls.from_dict(data)

    def evaluate(self, tool: str, inputs, principal: Optional[str],
                 authorized: Optional[bool], identity=None) -> Decision:
        reasons: list = []

        # 1. 全局急停优先级最高
        if self.killswitch:
            return Decision("block", ["Kill-switch engaged; all tool calls are blocked"])

        # 2. 显式拒绝
        if tool in self.deny_tools:
            return Decision("block", [f"Tool `{tool}` is on the deny list"])

        # 3. 白名单(若启用)
        if self.allow_tools is not None and tool not in self.allow_tools:
            return Decision("block", [f"Tool `{tool}` is not on the allow list (least-privilege)"])

        # 4. 需授权
        if tool in self.require_auth_tools and not authorized:
            return Decision("block",
                            [f"Tool `{tool}` requires authorization, but principal "
                             f"`{principal or 'anonymous'}` is not authorized"])

        # 4.5 基于身份/委托的 scope 授权(MCP-SP §2.10)。
        # 仅当为该工具配置了 tool_scopes 才生效——授权判定基于「委托衰减后的有效授权」，
        # 即委托链上各主体 grants 的交集，确保 agent 代表他人行动时权限只收窄不放大。
        required = self.tool_scopes.get(tool)
        if required:
            if identity is None:
                return Decision("block",
                                [f"Tool `{tool}` requires scope(s) {sorted(required)} "
                                 f"but no identity/grants were provided"])
            eff = identity.effective_grants()
            missing = set(required) - set(eff)
            if missing:
                return Decision("block",
                                [f"Tool `{tool}` requires scope(s) {sorted(missing)} not held "
                                 f"by `{identity.subject}` (effective grants after delegation: "
                                 f"{sorted(eff)})"])

        # 5. 破坏性操作闸门
        if tool in self.destructive_tools and not self.allow_destructive:
            return Decision("block",
                            [f"Tool `{tool}` is a destructive operation and was blocked "
                             f"(allow_destructive=False)"])

        return Decision("allow", reasons)
