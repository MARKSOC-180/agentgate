"""CLI 集成测试(扩展覆盖)。"""

import json
import subprocess
import sys

from agentgate.gateway import Gateway
from agentgate.policy import Policy


def _run(*args):
    return subprocess.run([sys.executable, "-m", "agentgate.cli", *args],
                          capture_output=True, text=True, encoding="utf-8")


def test_version():
    r = _run("version")
    assert r.returncode == 0
    assert "0.2" in r.stdout


def test_verify_empty(tmp_path):
    audit = tmp_path / "empty.ndjson"
    audit.write_text("", encoding="utf-8")
    r = _run("verify", str(audit))
    assert r.returncode == 0


def test_export_command(tmp_path):
    audit = tmp_path / "a.ndjson"
    gw = Gateway(policy=Policy(), audit_path=str(audit),
                 trace_path=str(tmp_path / "t.ndjson"))
    gw.call("x", {}, handler=lambda i: 1)
    out = tmp_path / "out"
    r = _run("export", str(audit), "--out", str(out))
    assert r.returncode == 0
    assert (out / "audit_export.json").exists()
    assert (out / "audit_export.cef").exists()


def test_conformance_command(tmp_path):
    audit = tmp_path / "a.ndjson"
    gw = Gateway(policy=Policy(), audit_path=str(audit),
                 trace_path=str(tmp_path / "t.ndjson"))
    gw.call("x", {}, handler=lambda i: 1)
    r = _run("conformance", str(audit))
    assert r.returncode == 0
    assert "Level" in r.stdout or "level" in r.stdout.lower()


def test_report_command(tmp_path):
    audit = tmp_path / "a.ndjson"
    gw = Gateway(policy=Policy(), audit_path=str(audit),
                 trace_path=str(tmp_path / "t.ndjson"))
    gw.call("x", {}, handler=lambda i: 1)
    html = tmp_path / "r.html"
    r = _run("report", str(audit), "--out", str(html))
    assert r.returncode == 0
    assert html.exists()


def test_anchor_command(tmp_path):
    audit = tmp_path / "a.ndjson"
    gw = Gateway(policy=Policy(), audit_path=str(audit),
                 trace_path=str(tmp_path / "t.ndjson"))
    gw.call("x", {}, handler=lambda i: 1)
    out = tmp_path / "anchors.ndjson"
    r = _run("anchor", str(audit), "--out", str(out))
    assert r.returncode == 0
    assert out.exists()


def test_approvals_list_and_approve(tmp_path):
    from agentgate.approvals import ApprovalStore
    store = ApprovalStore(str(tmp_path / "appr.json"))
    aid = store.request("delete_records", "agent", reason="test")
    r = _run("approvals", "list", "--pending", "--store", str(tmp_path / "appr.json"))
    assert r.returncode == 0
    assert aid in r.stdout
    r2 = _run("approvals", "approve", aid, "--store", str(tmp_path / "appr.json"))
    assert r2.returncode == 0


def test_conformance_json_and_require_fail(tmp_path):
    audit = tmp_path / "a.ndjson"
    gw = Gateway(policy=Policy(), audit_path=str(audit),
                 trace_path=str(tmp_path / "t.ndjson"))
    gw.call("x", {}, handler=lambda i: 1)
    r = _run("conformance", str(audit), "--json")
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert "level" in data
    r2 = _run("conformance", str(audit), "--require", "3")
    assert r2.returncode != 0


def test_metrics_command(tmp_path):
    audit = tmp_path / "a.ndjson"
    gw = Gateway(policy=Policy(), audit_path=str(audit),
                 trace_path=str(tmp_path / "t.ndjson"))
    gw.call("x", {}, handler=lambda i: 1)
    r = _run("metrics", str(audit))
    assert r.returncode == 0
    assert "agentgate_calls_total" in r.stdout
