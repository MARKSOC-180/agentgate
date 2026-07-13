"""policy.py 的单元测试：策略引擎。"""

import json

from agentgate.policy import Policy


def test_default_allows_unknown_tool():
    assert Policy().evaluate("anything", {}, None, None).allowed


def test_deny_list_blocks():
    p = Policy(deny_tools={"shell_exec"})
    assert not p.evaluate("shell_exec", {}, None, None).allowed


def test_allow_list_is_whitelist():
    p = Policy(allow_tools={"web_search"})
    assert p.evaluate("web_search", {}, None, None).allowed
    assert not p.evaluate("read_db", {}, None, None).allowed


def test_require_auth():
    p = Policy(require_auth_tools={"issue_refund"})
    assert not p.evaluate("issue_refund", {}, "u1", False).allowed
    assert p.evaluate("issue_refund", {}, "u1", True).allowed


def test_destructive_blocked_unless_allowed():
    p = Policy(destructive_tools={"delete_records"})
    assert not p.evaluate("delete_records", {}, "u1", True).allowed
    p.allow_destructive = True
    assert p.evaluate("delete_records", {}, "u1", True).allowed


def test_killswitch_blocks_everything():
    p = Policy(killswitch=True)
    assert not p.evaluate("web_search", {}, None, None).allowed


def test_from_dict():
    p = Policy.from_dict({
        "deny_tools": ["shell_exec"],
        "require_auth_tools": ["issue_refund"],
        "destructive_tools": ["delete_records"],
        "allow_destructive": False,
    })
    assert "shell_exec" in p.deny_tools
    assert "issue_refund" in p.require_auth_tools
    assert p.allow_tools is None


def test_from_file(tmp_path):
    cfg = tmp_path / "p.json"
    cfg.write_text(json.dumps({"policy": {"deny_tools": ["x"]}}), encoding="utf-8")
    p = Policy.from_file(str(cfg))
    assert "x" in p.deny_tools
