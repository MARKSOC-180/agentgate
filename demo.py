"""
demo.py —— AgentGate 端到端演示。

模拟一个"客服 agent"跑一次任务，过程中做了几件危险的事：
  - 读到了含密钥 + 客户 PII 的数据(应被脱敏)
  - 未授权就想发起退款(应被拦)
  - 想无条件批量删除记录(破坏性，应被拦)
  - 想执行危险 shell(应被拦)

AgentGate 全程把关，最后产出一份「它帮你拦下了什么」的本地报告 + 不可篡改审计链。

运行(零外部依赖)：
    python demo.py
然后浏览器打开生成的 agentgate_report.html
"""

import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from agentgate import Gateway, Policy, Limiter, RateLimit, ApprovalStore, Alerter, Anchor

HERE = os.path.dirname(os.path.abspath(__file__))
AUDIT = os.path.join(HERE, "data", "audit.ndjson")
TRACE = os.path.join(HERE, "data", "trace.ndjson")
APPROVALS = os.path.join(HERE, "data", "approvals.json")
ANCHORS = os.path.join(HERE, "data", "anchors.ndjson")


# ---- 模拟一些工具(MCP server / 函数都一样) ----
def web_search(inputs):
    return ["AI agent observability market is growing", "self-hosted is trending"]

def read_customer_record(inputs):
    # 这条返回里"不小心"带了密钥和 PII —— 真实世界天天发生
    return {
        "name": "Jane Doe",
        "email": "jane.doe@example.com",
        "phone": "+1 415 555 0182",
        "card": "4242 4242 4242 4242",
        "internal_note": "service key sk-proj-AbCdEf0123456789XyZ used for sync",
    }

def issue_refund(inputs):
    return {"refunded": True, "order": inputs.get("order")}

def delete_records(inputs):
    return {"deleted": "all"}

def shell_exec(inputs):
    return {"ran": inputs.get("cmd")}


def main():
    for p in (AUDIT, TRACE, APPROVALS, ANCHORS):
        if os.path.exists(p):
            os.remove(p)

    # 一份合理的生产策略 + 顶级控制：限流/预算、人在环审批、实时告警
    policy = Policy(
        require_auth_tools={"issue_refund"},
        require_approval_tools={"delete_records"},     # 删除需人工审批(人在环)
        destructive_tools={"delete_records", "shell_exec"},
        allow_destructive=False,
    )
    limits = Limiter(
        default_rate=RateLimit(max_calls=3, window=60),   # 每工具默认 3 次/分
        max_cost=10.0,                                     # 累计成本预算 $10
    )
    alerts = Alerter(on=("block", "critical"))             # 拦截/critical 触发告警
    approvals = ApprovalStore(APPROVALS)
    anchor = Anchor(ANCHORS)                               # 审计链外部锚定
    gate = Gateway(policy=policy, audit_path=AUDIT, trace_path=TRACE,
                   limits=limits, alerts=alerts, approvals=approvals,
                   anchor=anchor, anchor_every=3)          # 每 3 条自动锚一次

    print("→ agent 开始工作，AgentGate 全程把关 ...\n")

    # 1. 正常搜索 —— 放行
    r = gate.call("web_search", {"q": "agent observability"},
                  handler=web_search, principal="agent-csr", authorized=True)
    print(f"  web_search           → {r.decision}")

    # 2. 读客户数据 —— 放行，但输出里的密钥/PII 被脱敏
    r = gate.call("read_customer_record", {"customer_id": "c-204"},
                  handler=read_customer_record, principal="agent-csr", authorized=True)
    print(f"  read_customer_record → {r.decision}，脱敏命中: {r.redaction_hits}")

    # 3. 未授权退款 —— 拦截
    r = gate.call("issue_refund", {"order": "o-1", "amount": 50},
                  handler=issue_refund, principal="agent-csr", authorized=False)
    print(f"  issue_refund         → {r.decision}：{r.reasons}")

    # 4. 批量删除(破坏性) —— 进入人工审批队列，不直接执行
    r = gate.call("delete_records", {"query": "DELETE FROM orders"},
                  handler=delete_records, principal="agent-csr", authorized=True)
    print(f"  delete_records       → {r.decision}（已转人工审批）")

    # 5. 危险 shell —— 拦截(critical 安全风险)
    r = gate.call("shell_exec", {"cmd": "rm -rf /"},
                  handler=shell_exec, principal="agent-csr", authorized=True)
    print(f"  shell_exec           → {r.decision}：{r.reasons}")

    # 6. 失控刷调用 —— 第 4 次被限流拦下(防烧钱/刷爆 API)
    for i in range(4):
        r = gate.call("web_search", {"q": f"loop-{i}"},
                      handler=web_search, principal="runaway-agent", authorized=True)
    print(f"  web_search ×4(失控)  → 第 4 次: {r.decision}：{r.reasons}")

    # 校验审计链 + 外部锚定反查 + 顶级功能小结
    gate.anchor_now()                                       # 收尾再锚一次链尖
    ok, msg = gate.audit.verify()
    a_ok, a_msg = anchor.verify(gate.audit)
    print(f"\n→ 审计链校验：{'✓' if ok else '✗'} {msg}")
    print(f"→ 外部锚定反查：{'✓' if a_ok else '✗'} {a_msg}")
    print(f"→ 待人工审批队列：{len(approvals.pending())} 条（CLI: agentgate approvals list --pending）")
    print(f"→ 实时告警触发：{len(alerts._sent)} 次")

    # 生成报告(英文世界级 UI，含锚定状态)
    from agentgate import build_report
    report = build_report(AUDIT, out_path=os.path.join(HERE, "agentgate_report.html"),
                          anchor_path=ANCHORS)
    print(f"\n完成。浏览器打开：{report}")


if __name__ == "__main__":
    main()
