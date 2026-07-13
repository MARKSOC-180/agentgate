"""
示例 01 —— 库模式快速接入(含全部顶级功能)。

演示如何用一个 Gateway 同时挂上：策略、限流/预算、人在环审批、实时告警，
并把任意工具函数包成「受控工具」。运行：

    python examples/01_quickstart.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8")

from agentgate import Gateway, Policy, Limiter, RateLimit, ApprovalStore, Alerter


# 1) 声明策略：退款需授权+需审批+破坏性；删库破坏性
policy = Policy(
    require_auth_tools={"issue_refund"},
    require_approval_tools={"issue_refund"},     # 人在环：要人点头
    destructive_tools={"issue_refund", "delete_records"},
)

# 2) 配额/限流：每个工具默认 5 次/分；总成本预算 $20
limits = Limiter(default_rate=RateLimit(max_calls=5, window=60), max_cost=20.0)

# 3) 实时告警：被拦截或 critical 时触发(这里仅记录，可换成 webhook/命令)
alerts = Alerter(on=("block", "critical"))

# 4) 审批库(本地)
approvals = ApprovalStore("agentgate_approvals.json")

gate = Gateway(policy=policy, limits=limits, alerts=alerts, approvals=approvals)


def issue_refund(inputs):
    return f"已退款 ${inputs['amount']} 到订单 {inputs['order']}"


print("== 1. 退款(已授权但需人工审批) →应被拦截并登记 ==")
r = gate.call("issue_refund", {"order": "o-1", "amount": 30},
              handler=issue_refund, principal="agent-csr", authorized=True)
print("  decision:", r.decision, "| reasons:", r.reasons)

aid = approvals.pending()[-1]["id"]
print(f"\n== 2. 人工批准 {aid} 后再调用 →放行执行 ==")
approvals.approve(aid, approver="ops-alice")
r = gate.call("issue_refund", {"order": "o-1", "amount": 30},
              handler=issue_refund, principal="agent-csr", authorized=True,
              approval_id=aid)
print("  decision:", r.decision, "| output:", r.output)

print(f"\n触发的告警数: {len(alerts._sent)}")
print("审计链校验:", gate.audit.verify()[1])
