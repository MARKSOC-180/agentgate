"""
AgentGate —— 自托管的 AI Agent 控制平面 / 网关。

夹在 AI agent 与它调用的工具(MCP server / 函数)之间，每一次工具调用都经过它：
  1. 策略(policy)  —— 允许/拒绝、是否需授权、破坏性操作闸门、全局 kill-switch
  2. 脱敏(redact)  —— 输入与输出里的密钥/PII 双向脱敏，再也不会流进日志或下游
  3. 安全(safety)  —— 检测破坏性操作、注入、越权
  4. 审计(audit)   —— 哈希链、不可篡改、可验证(满足 SOC2/AI Act 审计)
  5. 追踪(trace)   —— 每次调用的结构化记录

设计铁律：
- 自托管 / 本地优先：一切跑在你自己墙内，数据零外泄(托管 SaaS 巨头进不来的缝)。
- 零外部依赖：纯标准库，谁的墙内都能跑，无供应链风险。
- 框架无关：一行 wrap 即可接入任意工具 / MCP 调用。
"""

from .gateway import Gateway, Blocked
from .policy import Policy, Decision
from .redact import redact
from .safety import scan_safety
from .audit import AuditLog
from .report import build_report
from .compliance import export_compliance
from .mcp_proxy import MCPProxy, build_proxy_from_config
from .limits import Limiter, RateLimit
from .approvals import ApprovalStore
from .alerts import Alerter
from .metrics import prometheus_text, collect
from .anchoring import Anchor
from .metering import Pricing, usage_report, billing_csv, Meter
from .intel import ThreatIntel
from .conformance import check_conformance, badge_markdown
from .identity import Identity, Principal, PrincipalResolver, register_resolver, resolve_token, load_resolver_module
from .http_sidecar import start_http_sidecar

__version__ = "0.2.0"
__all__ = [
    "Gateway", "Blocked",
    "Policy", "Decision",
    "redact", "scan_safety",
    "AuditLog", "build_report",
    "export_compliance",
    "MCPProxy", "build_proxy_from_config",
    "Limiter", "RateLimit",
    "ApprovalStore", "Alerter",
    "prometheus_text", "collect",
    "Anchor",
    "Pricing", "usage_report", "billing_csv", "Meter",
    "ThreatIntel",
    "check_conformance", "badge_markdown",
    "Identity", "Principal", "PrincipalResolver", "register_resolver", "resolve_token", "load_resolver_module",
    "start_http_sidecar",
]
