"""
identity.py —— 身份与委托模型(MCP-SP §2.10 的实现)。

为什么需要它：agent 场景里，「谁在调用」从来不是一个字符串能说清的。一个 agent
往往**代表**某个人或服务行动(on-behalf-of)，而它能做的，绝不该超过它所代表的那个
主体本身被授予的权限。把这件事建模清楚，是「谁、以什么权限、代表谁、能做什么」
这条治理主线的地基。

核心是 **capability 安全的衰减原则(attenuation)**：
    委托只能收窄权限，绝不能放大。
一次调用的**有效授权** = 委托链上所有主体被授予权限的**交集**。于是 agent 代表
user 行动时，有效权限 = (agent 自己的 grants) ∩ (user 的 grants)——既不能越过 user，
也不能越过 agent 自身被授予的范围。

这个模型刻意保持最小：只引入 subject / 委托链 / grants(scopes) 与衰减，不拖入整个
OAuth。它与字符串 principal **完全向后兼容**：不提供 Identity 时，一切行为如旧。

纯标准库。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Principal:
    """一个主体：发起或被代表的身份。

    type ∈ {user, service, agent}；grants 是它被授予的能力(scope)集合。
    """
    id: str
    type: str = "agent"
    grants: frozenset = field(default_factory=frozenset)

    @classmethod
    def from_dict(cls, data) -> "Principal":
        if isinstance(data, str):
            return cls(id=data)
        data = data or {}
        return cls(id=data.get("id", "anonymous"),
                   type=data.get("type", "agent"),
                   grants=frozenset(data.get("grants", []) or []))


@dataclass
class Identity:
    """一次调用的完整身份上下文：主体 + 委托链。

        Identity(Principal("agent-csr", "agent", {"read:customer"}),
                 on_behalf_of=[Principal("user-42", "user",
                                         {"read:customer", "refund:create"})])
    """
    principal: Principal
    on_behalf_of: List[Principal] = field(default_factory=list)

    def chain(self) -> List[Principal]:
        return [self.principal] + list(self.on_behalf_of)

    def effective_grants(self) -> frozenset:
        """委托衰减后的有效授权 = 链上所有主体 grants 的交集。"""
        sets = [p.grants for p in self.chain()]
        if not sets:
            return frozenset()
        out = set(sets[0])
        for s in sets[1:]:
            out &= set(s)
        return frozenset(out)

    @property
    def subject(self) -> str:
        """这次行动**最终代表**的主体(委托链尾)——用于审计「替谁做事」。"""
        return self.on_behalf_of[-1].id if self.on_behalf_of else self.principal.id

    def to_record(self) -> dict:
        """脱敏友好的审计表示：只记 id/type/grants 与委托链，不含任何敏感载荷。"""
        return {
            "subject": self.subject,
            "actor": self.principal.id,
            "delegation": [p.id for p in self.chain()],
            "granted": sorted(self.effective_grants()),
        }

    @classmethod
    def from_dict(cls, data) -> "Identity":
        if isinstance(data, str):
            return cls(Principal(id=data))
        data = data or {}
        return cls(
            principal=Principal.from_dict(data.get("principal", data)),
            on_behalf_of=[Principal.from_dict(p)
                          for p in (data.get("on_behalf_of", []) or [])],
        )


def coerce_identity(principal) -> Optional[Identity]:
    """把调用方传入的 principal 归一为 Identity。

    - Identity / Principal -> 直接采用(或包一层)
    - 其它(字符串 / None) -> 返回 None(走旧的字符串 principal 路径，完全向后兼容)
    """
    if isinstance(principal, Identity):
        return principal
    if isinstance(principal, Principal):
        return Identity(principal)
    return None


def load_resolver_module(module_path: str) -> None:
    """从 dotted module path 加载 resolver(模块 import 时应 register_resolver)。"""
    import importlib
    importlib.import_module(module_path)


def principal_id(principal) -> Optional[str]:
    """提取用于审计 `principal` 字段的字符串 id(保持与旧行为一致：字符串/None 原样返回)。"""
    if isinstance(principal, Identity):
        return principal.principal.id
    if isinstance(principal, Principal):
        return principal.id
    return principal


# ---- 插件钩子：OIDC / SPIFFE / 企业 IdP 适配入口 ----

class PrincipalResolver:
    """把外部凭证(如 OIDC access token、SPIFFE JWT)解析为 Identity 的插件接口。

    用法：
        class MyOidcResolver(PrincipalResolver):
            def resolve(self, token: str) -> Optional[Identity]:
                claims = verify_jwt(token)  # 你的 IdP 逻辑
                return Identity(Principal(claims["sub"], "user", frozenset(claims["scope"])))

        register_resolver(MyOidcResolver())
    """

    def resolve(self, token: str) -> Optional[Identity]:
        raise NotImplementedError


_RESOLVER: Optional[PrincipalResolver] = None


def register_resolver(resolver: PrincipalResolver) -> None:
    """注册全局 PrincipalResolver(后注册覆盖先注册)。"""
    global _RESOLVER
    _RESOLVER = resolver


def get_resolver() -> Optional[PrincipalResolver]:
    return _RESOLVER


def resolve_token(token: str) -> Optional[Identity]:
    """若已注册 resolver，用 token 解析 Identity；否则返回 None。"""
    if _RESOLVER is None or not token:
        return None
    return _RESOLVER.resolve(token)
