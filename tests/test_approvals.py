"""approvals.py 的单元测试：人在环审批。"""

from agentgate.approvals import ApprovalStore, PENDING, APPROVED, DENIED


def _store(tmp_path):
    return ApprovalStore(str(tmp_path / "approvals.json"))


def test_request_creates_pending(tmp_path):
    s = _store(tmp_path)
    aid = s.request("delete_records", "u", reason="r")
    assert s.status(aid) == PENDING
    rec = s.get(aid)
    assert rec["tool"] == "delete_records"
    assert rec["principal"] == "u"


def test_approve(tmp_path):
    s = _store(tmp_path)
    aid = s.request("t", "u")
    assert s.approve(aid, "alice") is True
    assert s.status(aid) == APPROVED
    assert s.get(aid)["approver"] == "alice"


def test_deny(tmp_path):
    s = _store(tmp_path)
    aid = s.request("t", "u")
    assert s.deny(aid) is True
    assert s.status(aid) == DENIED


def test_cannot_decide_twice(tmp_path):
    s = _store(tmp_path)
    aid = s.request("t", "u")
    assert s.approve(aid) is True
    assert s.deny(aid) is False          # 已决策，不能再改
    assert s.status(aid) == APPROVED


def test_pending_list(tmp_path):
    s = _store(tmp_path)
    a = s.request("t1", "u")
    s.request("t2", "u")
    s.approve(a)
    pend = s.pending()
    assert len(pend) == 1
    assert pend[0]["tool"] == "t2"


def test_unknown_id(tmp_path):
    s = _store(tmp_path)
    assert s.status("nope") is None
    assert s.approve("nope") is False
