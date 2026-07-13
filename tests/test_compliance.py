"""compliance.py 的单元测试：合规导出。"""

import os

from agentgate.gateway import Gateway
from agentgate.policy import Policy
from agentgate.compliance import export_compliance


def test_export_produces_files_and_stats(tmp_path):
    audit = str(tmp_path / "audit.ndjson")
    gw = Gateway(policy=Policy(deny_tools={"danger"}),
                 audit_path=audit, trace_path=str(tmp_path / "trace.ndjson"))
    gw.call("read", {"e": "x@y.com"}, handler=lambda i: "ok")   # allow + 脱敏
    gw.call("danger", {}, handler=lambda i: "no")               # block

    out_dir = str(tmp_path / "out")
    info = export_compliance(audit, out_dir=out_dir)

    assert os.path.exists(info["report_path"])
    assert os.path.exists(info["csv_path"])
    assert os.path.exists(info["json_path"])
    assert os.path.exists(info["cef_path"])
    assert info["chain_ok"] is True
    assert info["total"] == 2
    assert info["allowed"] == 1
    assert info["blocked"] == 1

    cef = open(info["cef_path"], encoding="utf-8").read()
    assert cef.startswith("CEF:0|AgentGate|")
    report = open(info["report_path"], encoding="utf-8").read()
    assert "PASS" in report
    assert "SOC2" in report


def test_export_reports_tamper(tmp_path):
    audit = tmp_path / "audit.ndjson"
    gw = Gateway(policy=Policy(), audit_path=str(audit),
                 trace_path=str(tmp_path / "trace.ndjson"))
    gw.call("a", {}, handler=lambda i: 1)
    gw.call("b", {}, handler=lambda i: 2)

    lines = audit.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"tool": "a"', '"tool": "HACKED"')
    audit.write_text("\n".join(lines) + "\n", encoding="utf-8")

    info = export_compliance(str(audit), out_dir=str(tmp_path / "out"))
    assert info["chain_ok"] is False
