"""intel.py 威胁情报数据飞轮测试：埋点、隐私安全、聚合、匿名导出。"""

from agentgate.gateway import Gateway
from agentgate.policy import Policy
from agentgate.intel import ThreatIntel


def _gw(tmp_path, ti):
    return Gateway(policy=Policy(deny_tools={"danger"}),
                   audit_path=str(tmp_path / "a.ndjson"),
                   trace_path=str(tmp_path / "t.ndjson"),
                   intel=ti)


def test_records_only_blocks_and_high_severity(tmp_path):
    ti = ThreatIntel(str(tmp_path / "intel.ndjson"))
    gw = _gw(tmp_path, ti)
    gw.call("read", {"x": 1}, handler=lambda i: "ok", principal="a")          # allow, low -> 不记
    gw.call("danger", {}, handler=lambda i: "no", principal="b")              # block -> 记
    gw.call("run_sql", {"sql": "DELETE FROM t"}, handler=lambda i: 1,
            principal="c")                                                    # critical -> 记
    recs = ti.load()
    assert len(recs) == 2
    decisions = {r["decision"] for r in recs}
    assert "block" in decisions


def test_no_cleartext_leaks_into_intel(tmp_path):
    ti = ThreatIntel(str(tmp_path / "intel.ndjson"))
    gw = _gw(tmp_path, ti)
    secret = "sk-SUPERSECRETVALUE12345"
    gw.call("danger", {"token": secret, "email": "boss@corp.com"},
            handler=lambda i: "no", principal="attacker")
    raw = open(str(tmp_path / "intel.ndjson"), encoding="utf-8").read()
    # 明文密钥/PII 绝不能出现在情报记录里
    assert secret not in raw
    assert "boss@corp.com" not in raw
    # 但结构哈希与签名应在
    assert "shape" in raw and "indicators" in raw


def test_summarize_and_signatures(tmp_path):
    ti = ThreatIntel(str(tmp_path / "intel.ndjson"))
    gw = _gw(tmp_path, ti)
    gw.call("danger", {}, handler=lambda i: "no", principal="b")
    gw.call("danger", {}, handler=lambda i: "no", principal="b")
    s = ti.summarize()
    assert s["events"] == 2
    assert s["blocks"] == 2
    sigs = dict(s["top_threats"])
    assert any(k.startswith("policy:") for k in sigs)
    assert s["by_tool"].get("danger") == 2


def test_export_feed_strips_principal(tmp_path):
    ti = ThreatIntel(str(tmp_path / "intel.ndjson"))
    gw = _gw(tmp_path, ti)
    gw.call("danger", {}, handler=lambda i: "no", principal="secret-identity")
    feed = ti.export_feed()
    assert feed["schema"].startswith("agentgate-intel-feed")
    assert feed["events"] == 1
    # 匿名导出不得泄露 principal
    import json
    assert "secret-identity" not in json.dumps(feed)
