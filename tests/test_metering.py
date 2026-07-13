"""metering.py 的单元测试：按调用量计费、从审计链派生账单。"""

import csv

from agentgate.gateway import Gateway
from agentgate.policy import Policy
from agentgate.metering import Pricing, usage_report, billing_csv


def _gw_with_data(tmp_path):
    audit = str(tmp_path / "audit.ndjson")
    gw = Gateway(policy=Policy(deny_tools={"danger"}),
                 audit_path=audit, trace_path=str(tmp_path / "trace.ndjson"))
    # alice：2 次放行(其中一次含 PII 脱敏)
    gw.call("read", {"e": "a@b.com"}, handler=lambda i: "ok", principal="alice")
    gw.call("read", {}, handler=lambda i: "ok", principal="alice")
    # bob：1 次放行 + 1 次拦截
    gw.call("read", {}, handler=lambda i: "ok", principal="bob")
    gw.call("danger", {}, handler=lambda i: "no", principal="bob")
    return audit


def test_usage_report_by_principal(tmp_path):
    audit = _gw_with_data(tmp_path)
    rep = usage_report(audit, Pricing(price_per_call=0.01), by="principal")
    rows = rep["rows"]
    assert rows["alice"]["calls"] == 2
    assert rows["alice"]["allow"] == 2
    assert rows["alice"]["redactions"] >= 1
    assert rows["bob"]["calls"] == 2
    assert rows["bob"]["block"] == 1
    # 默认 allow+block 都计费：alice 2 次、bob 2 次，共 4 次 * 0.01
    assert rep["totals"]["calls"] == 4
    assert abs(rep["totals"]["amount"] - 0.04) < 1e-9
    assert rep["verifiable"] is True


def test_free_tier_per_principal(tmp_path):
    audit = _gw_with_data(tmp_path)
    # 每个 principal 前 2 次免费 -> alice(2) 全免，bob(2) 全免 -> 0
    rep = usage_report(audit, Pricing(price_per_call=0.01, included_calls=2))
    assert rep["totals"]["amount"] == 0.0
    assert rep["rows"]["alice"]["billable_charged"] == 0


def test_billable_decisions_allow_only(tmp_path):
    audit = _gw_with_data(tmp_path)
    rep = usage_report(audit, Pricing(price_per_call=1.0,
                                      billable_decisions=("allow",)))
    # 仅放行计费：alice 2 + bob 1 = 3
    assert rep["totals"]["billable"] == 3
    assert rep["totals"]["amount"] == 3.0


def test_by_tool(tmp_path):
    audit = _gw_with_data(tmp_path)
    rep = usage_report(audit, Pricing(price_per_call=0.0), by="tool")
    assert rep["rows"]["read"]["calls"] == 3
    assert rep["rows"]["danger"]["calls"] == 1


def test_billing_csv(tmp_path):
    audit = _gw_with_data(tmp_path)
    rep = usage_report(audit, Pricing(price_per_call=0.01))
    out = str(tmp_path / "invoice.csv")
    billing_csv(rep, out)
    with open(out, encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows[0][0] == "principal"
    assert rows[-1][0] == "TOTAL"
    keys = {r[0] for r in rows}
    assert "alice" in keys and "bob" in keys
