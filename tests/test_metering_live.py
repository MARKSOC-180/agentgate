"""metering.Meter 实时计量器 + Gateway 实时计费集成测试。"""

import json

from agentgate.gateway import Gateway
from agentgate.policy import Policy
from agentgate.metering import Meter, Pricing


def test_meter_record_and_snapshot(tmp_path):
    usage = str(tmp_path / "usage.ndjson")
    m = Meter(Pricing(price_per_call=0.01), usage_path=usage)
    m.record("alice", "read", "allow", redactions=2)
    m.record("alice", "read", "allow")
    m.record("bob", "danger", "block")
    snap = m.snapshot()
    assert snap["live"] is True
    assert snap["rows"]["alice"]["calls"] == 2
    assert snap["rows"]["alice"]["redactions"] == 2
    assert snap["rows"]["bob"]["block"] == 1
    assert abs(snap["totals"]["amount"] - 0.03) < 1e-9
    # usage 日志已落盘，每次调用一行
    lines = [l for l in open(usage, encoding="utf-8").read().splitlines() if l.strip()]
    assert len(lines) == 3
    assert json.loads(lines[0])["principal"] == "alice"


def test_gateway_realtime_metering(tmp_path):
    meter = Meter(Pricing(price_per_call=1.0))
    gw = Gateway(policy=Policy(deny_tools={"danger"}),
                 audit_path=str(tmp_path / "a.ndjson"),
                 trace_path=str(tmp_path / "t.ndjson"),
                 meter=meter)
    gw.call("read", {"e": "x@y.com"}, handler=lambda i: "ok", principal="alice")
    gw.call("danger", {}, handler=lambda i: "no", principal="bob")
    snap = meter.snapshot()
    assert snap["totals"]["calls"] == 2
    assert snap["rows"]["alice"]["allow"] == 1
    assert snap["rows"]["alice"]["redactions"] >= 1
    assert snap["rows"]["bob"]["block"] == 1
    assert snap["totals"]["amount"] == 2.0   # allow + block 都计费
