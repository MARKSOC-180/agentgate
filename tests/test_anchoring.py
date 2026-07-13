"""anchoring.py 的单元测试：审计链外部锚定。"""

import json

from agentgate.gateway import Gateway
from agentgate.policy import Policy
from agentgate.anchoring import Anchor


def _gw(tmp_path, **kw):
    return Gateway(policy=Policy(), audit_path=str(tmp_path / "audit.ndjson"),
                   trace_path=str(tmp_path / "trace.ndjson"), **kw)


def test_anchor_and_verify_ok(tmp_path):
    anc = Anchor(str(tmp_path / "anchors.ndjson"))
    gw = _gw(tmp_path)
    for _ in range(3):
        gw.call("t", {}, handler=lambda i: 1)
    rec = anc.anchor(gw.audit)
    assert rec["count"] == 3
    ok, _ = anc.verify(gw.audit)
    assert ok


def test_detects_history_rewrite_even_when_chain_recomputed(tmp_path):
    """管理员重写历史并重算整条链 → audit.verify() 会通过，但锚点反查能抓到。"""
    audit_path = tmp_path / "audit.ndjson"
    anc = Anchor(str(tmp_path / "anchors.ndjson"))
    gw = _gw(tmp_path)
    for _ in range(2):
        gw.call("read", {}, handler=lambda i: 1)
    anc.anchor(gw.audit)                        # 锚定前 2 条
    gw.call("read", {}, handler=lambda i: 1)    # 再来一条

    # 模拟管理员重写第 1 条并重算整条链(使 audit.verify 仍通过)
    from agentgate.audit import AuditLog
    log = AuditLog(str(audit_path))
    records = log.load()
    records[0]["tool"] = "TAMPERED"
    prev = "GENESIS"
    lines = []
    for r in records:
        body = {k: v for k, v in r.items() if k != "this_hash"}
        body["prev_hash"] = prev
        h = AuditLog._hash(prev, body)
        prev = h
        lines.append(json.dumps({**body, "this_hash": h}, ensure_ascii=False))
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 内部链校验被骗过
    assert AuditLog(str(audit_path)).verify()[0] is True
    # 但外部锚点反查抓到历史被重写
    ok, msg = anc.verify(AuditLog(str(audit_path)))
    assert ok is False
    assert "rewritten" in msg or "history" in msg


def test_anchor_chain_self_integrity(tmp_path):
    anc = Anchor(str(tmp_path / "anchors.ndjson"))
    gw = _gw(tmp_path)
    gw.call("t", {}, handler=lambda i: 1)
    anc.anchor(gw.audit)
    gw.call("t", {}, handler=lambda i: 1)
    anc.anchor(gw.audit)
    ok, msg = anc.verify_anchor_chain()
    assert ok
    assert "2 anchors" in msg


def test_auto_anchor_every(tmp_path):
    anc = Anchor(str(tmp_path / "anchors.ndjson"))
    gw = _gw(tmp_path, anchor=anc, anchor_every=2)
    for _ in range(4):
        gw.call("t", {}, handler=lambda i: 1)
    assert len(anc.records()) == 2          # 第 2、4 条各锚一次
    ok, _ = anc.verify(gw.audit)
    assert ok


def test_sink_is_called(tmp_path):
    pushed = []
    anc = Anchor(str(tmp_path / "anchors.ndjson"), sink=lambda rec: pushed.append(rec))
    gw = _gw(tmp_path)
    gw.call("t", {}, handler=lambda i: 1)
    anc.anchor(gw.audit)
    assert len(pushed) == 1
    assert "audit_head" in pushed[0]
