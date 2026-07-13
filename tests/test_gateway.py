"""gateway.py 的单元测试：控制平面主流水线。"""

import pytest

from agentgate.gateway import Gateway, Blocked
from agentgate.policy import Policy


def _gw(tmp_path, **policy_kw):
    return Gateway(
        policy=Policy(**policy_kw),
        audit_path=str(tmp_path / "audit.ndjson"),
        trace_path=str(tmp_path / "trace.ndjson"),
    )


def test_allowed_call_executes_handler(tmp_path):
    gw = _gw(tmp_path)
    seen = {}

    def handler(inp):
        seen["ran"] = True
        return {"ok": True, "leak": "x@y.com"}

    r = gw.call("read", {"id": 1}, handler=handler)
    assert r.decision == "allow"
    assert seen.get("ran") is True
    # 输出里的邮箱被脱敏
    assert "x@y.com" not in str(r.output)
    assert r.redaction_hits.get("Email") == 1


def test_blocked_call_does_not_execute_handler(tmp_path):
    gw = _gw(tmp_path, deny_tools={"danger"})
    seen = {"ran": False}

    def handler(inp):
        seen["ran"] = True
        return "should-not-run"

    r = gw.call("danger", {}, handler=handler)
    assert r.decision == "block"
    assert seen["ran"] is False
    assert r.output is None


def test_raise_on_block(tmp_path):
    gw = _gw(tmp_path, deny_tools={"danger"})
    with pytest.raises(Blocked):
        gw.call("danger", {}, handler=lambda i: 1, raise_on_block=True)


def test_critical_safety_upgrades_to_block(tmp_path):
    gw = _gw(tmp_path)  # 默认放行，但 critical 安全发现应强制拦截
    r = gw.call("run_sql", {"sql": "DELETE FROM users"}, handler=lambda i: "done")
    assert r.decision == "block"


def test_audit_chain_grows_and_verifies(tmp_path):
    gw = _gw(tmp_path)
    gw.call("a", {}, handler=lambda i: 1)
    gw.call("b", {}, handler=lambda i: 2)
    ok, _ = gw.audit.verify()
    assert ok
    assert len(gw.audit.load()) == 2


def test_killswitch(tmp_path):
    gw = _gw(tmp_path)
    gw.kill()
    assert gw.call("anything", {}, handler=lambda i: 1).decision == "block"
    gw.resume()
    assert gw.call("anything", {}, handler=lambda i: 1).decision == "allow"


def test_wrap(tmp_path):
    gw = _gw(tmp_path, require_auth_tools={"refund"})
    safe = gw.wrap("refund", lambda i: "paid", destructive=True)
    assert safe({"amount": 1}, principal="u", authorized=False).decision == "block"
