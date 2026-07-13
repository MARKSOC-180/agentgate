"""conformance.py 测试：MCP-SP 一致性自检 + 徽章 + 篡改检测。"""

from agentgate.gateway import Gateway
from agentgate.policy import Policy
from agentgate.anchoring import Anchor
from agentgate.conformance import check_conformance, badge_markdown


def _make_log(tmp_path, with_anchor=False):
    audit = str(tmp_path / "audit.ndjson")
    anchors = str(tmp_path / "anchors.ndjson")
    anchor = Anchor(anchors) if with_anchor else None
    gw = Gateway(policy=Policy(deny_tools={"danger"}),
                 audit_path=audit, trace_path=str(tmp_path / "trace.ndjson"),
                 anchor=anchor)
    gw.call("read", {"e": "x@y.com"}, handler=lambda i: "ok", principal="a")
    gw.call("danger", {}, handler=lambda i: "no", principal="b")
    if with_anchor:
        gw.anchor_now()
    return audit, anchors


def test_reference_impl_reaches_level_2_from_log_alone(tmp_path):
    audit, _ = _make_log(tmp_path)
    res = check_conformance(audit)
    # 仅凭日志：schema + 链 + 策略 + 脱敏 + safety 字段 => Level 2，但无锚点不到 3
    assert res["level"] == 2
    assert res["level_name"] == "Governed"
    assert any("Tamper-evident" in p for p in res["passed"])
    assert any("Level 3" in f or "anchor" in f.lower() for f in res["failed"])


def test_level_3_with_anchors(tmp_path):
    audit, anchors = _make_log(tmp_path, with_anchor=True)
    res = check_conformance(audit, anchors_path=anchors)
    assert res["level"] == 3
    assert res["level_name"] == "Assured"


def test_tampering_breaks_conformance(tmp_path):
    audit, _ = _make_log(tmp_path)
    # 偷偷改掉一条记录的内容(不重算哈希) -> 链断 -> 跌出 Level 1
    lines = open(audit, encoding="utf-8").read().splitlines()
    lines[0] = lines[0].replace('"tool": "read"', '"tool": "HACKED"')
    with open(audit, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    res = check_conformance(audit)
    assert res["level"] == 0
    assert any("hash mismatch" in f or "chain" in f.lower() for f in res["failed"])


def test_empty_log_not_conformant(tmp_path):
    audit = str(tmp_path / "empty.ndjson")
    open(audit, "w").close()
    res = check_conformance(audit)
    assert res["level"] == 0


def test_identity_context_is_validated(tmp_path):
    """带 identity 的日志：一致 -> 不降级；伪造(subject 不符委托链) -> 跌到 Level 0。"""
    from agentgate.identity import Identity, Principal
    import json

    audit = str(tmp_path / "audit.ndjson")
    gw = Gateway(policy=Policy(), audit_path=audit,
                 trace_path=str(tmp_path / "t.ndjson"))
    ident = Identity(Principal("agent", "agent", frozenset({"read:customer"})),
                     on_behalf_of=[Principal("user-42", "user", frozenset({"read:customer"}))])
    gw.call("read", {"x": 1}, handler=lambda i: "ok", principal=ident)
    res = check_conformance(audit)
    assert res["level"] == 2
    assert any("Identity & delegation" in p for p in res["passed"])

    # 篡改 identity.subject 但保持 schema -> 重算哈希让链有效 -> 仍应被 §2.10 抓出
    import hashlib
    rec = json.loads(open(audit, encoding="utf-8").read().splitlines()[0])
    rec["identity"]["subject"] = "attacker"
    body = {k: v for k, v in rec.items() if k != "this_hash"}
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)
    rec["this_hash"] = hashlib.sha256(("GENESIS|" + canonical).encode()).hexdigest()
    with open(audit, "w", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    res2 = check_conformance(audit)
    assert res2["level"] == 0
    assert any("subject" in f for f in res2["failed"])


def test_badge_markdown_levels():
    assert "Level%203" in badge_markdown(3) and "brightgreen" in badge_markdown(3)
    assert "not%20conformant" in badge_markdown(0) and "-red" in badge_markdown(0)
    assert badge_markdown(2).startswith("[![MCP-SP](")
