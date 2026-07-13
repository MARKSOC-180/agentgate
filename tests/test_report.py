"""report.py HTML 报告生成测试。"""

from agentgate.gateway import Gateway
from agentgate.policy import Policy
from agentgate.report import build_report


def test_build_report_creates_html(tmp_path):
    audit = str(tmp_path / "a.ndjson")
    out = str(tmp_path / "r.html")
    gw = Gateway(policy=Policy(deny_tools={"bad"}), audit_path=audit,
                 trace_path=str(tmp_path / "t.ndjson"))
    gw.call("ok", {"x": 1}, handler=lambda i: "done", principal="u")
    gw.call("bad", {}, handler=lambda i: "nope", principal="u")
    path = build_report(audit, out_path=out)
    html = open(path, encoding="utf-8").read()
    assert "AgentGate" in html
    assert "blocked" in html.lower() or "Blocked" in html
