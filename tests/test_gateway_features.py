"""gateway 与顶级功能(审批/限流/告警)的集成测试。"""

from agentgate.gateway import Gateway
from agentgate.policy import Policy
from agentgate.limits import Limiter, RateLimit
from agentgate.approvals import ApprovalStore
from agentgate.alerts import Alerter


def _paths(tmp_path):
    return dict(audit_path=str(tmp_path / "audit.ndjson"),
                trace_path=str(tmp_path / "trace.ndjson"))


def test_approval_flow(tmp_path):
    store = ApprovalStore(str(tmp_path / "ap.json"))
    gw = Gateway(policy=Policy(require_approval_tools={"refund"}),
                 approvals=store, **_paths(tmp_path))

    ran = {"n": 0}
    handler = lambda i: ran.__setitem__("n", ran["n"] + 1) or "paid"

    # 首次：无审批 → 拦截 + 不执行 + 登记 pending
    r1 = gw.call("refund", {"amount": 10}, handler=handler)
    assert r1.decision == "block"
    assert ran["n"] == 0
    pend = store.pending()
    assert len(pend) == 1
    aid = pend[0]["id"]

    # 仍未批准前，带着 pending id 调用也应拦截
    assert gw.call("refund", {"amount": 10}, handler=handler, approval_id=aid).decision == "block"

    # 人工批准后，带 id 调用 → 放行 + 执行
    assert store.approve(aid, "alice") is True
    r2 = gw.call("refund", {"amount": 10}, handler=handler, approval_id=aid)
    assert r2.decision == "allow"
    assert ran["n"] == 1


def test_denied_approval_blocks(tmp_path):
    store = ApprovalStore(str(tmp_path / "ap.json"))
    gw = Gateway(policy=Policy(require_approval_tools={"refund"}),
                 approvals=store, **_paths(tmp_path))
    gw.call("refund", {"amount": 1}, handler=lambda i: 1)
    aid = store.pending()[0]["id"]
    store.deny(aid)
    r = gw.call("refund", {"amount": 1}, handler=lambda i: 1, approval_id=aid)
    assert r.decision == "block"
    assert "denied" in " ".join(r.reasons).lower()


def test_rate_limit_blocks_second_call(tmp_path):
    gw = Gateway(policy=Policy(),
                 limits=Limiter(default_rate=RateLimit(max_calls=1, window=60)),
                 **_paths(tmp_path))
    assert gw.call("t", {}, handler=lambda i: 1).decision == "allow"
    r = gw.call("t", {}, handler=lambda i: 1)
    assert r.decision == "block"
    assert "rate-limited" in " ".join(r.reasons).lower()


def test_cost_budget_blocks(tmp_path):
    gw = Gateway(policy=Policy(), limits=Limiter(max_cost=5.0), **_paths(tmp_path))
    assert gw.call("t", {}, handler=lambda i: 1, cost=4.0).decision == "allow"
    assert gw.call("t", {}, handler=lambda i: 1, cost=2.0).decision == "block"


def test_alert_fires_on_block(tmp_path):
    alerter = Alerter(on=("block",))  # 无通道，但会记录到 _sent
    gw = Gateway(policy=Policy(deny_tools={"danger"}), alerts=alerter, **_paths(tmp_path))
    gw.call("safe", {}, handler=lambda i: 1)      # allow → 不告警
    gw.call("danger", {}, handler=lambda i: 1)    # block → 告警
    assert len(alerter._sent) == 1
    assert alerter._sent[0]["tool"] == "danger"
