"""metrics.py 的单元测试：Prometheus 指标导出。"""

from agentgate.gateway import Gateway
from agentgate.policy import Policy
from agentgate.metrics import collect, prometheus_text


def _gw_with_data(tmp_path):
    audit = str(tmp_path / "audit.ndjson")
    gw = Gateway(policy=Policy(deny_tools={"danger"}),
                 audit_path=audit, trace_path=str(tmp_path / "trace.ndjson"))
    gw.call("read", {"e": "x@y.com"}, handler=lambda i: "ok")     # allow + redaction
    gw.call("danger", {}, handler=lambda i: "no")                 # block
    gw.call("run_sql", {"sql": "DELETE FROM t"}, handler=lambda i: 1)  # block(critical)
    return audit


def test_collect_counts(tmp_path):
    audit = _gw_with_data(tmp_path)
    m = collect(audit)
    assert m["records"] == 3
    assert m["decisions"]["allow"] == 1
    assert m["decisions"]["block"] == 2
    assert m["redactions"] >= 1
    assert m["severity"].get("critical", 0) >= 1
    assert m["chain_ok"] is True


def test_prometheus_text_format(tmp_path):
    audit = _gw_with_data(tmp_path)
    text = prometheus_text(audit)
    assert "# TYPE agentgate_calls_total counter" in text
    assert 'agentgate_calls_total{decision="block"} 2' in text
    assert "agentgate_audit_chain_ok 1" in text
    assert "agentgate_audit_records 3" in text
