"""identity.py + 基于身份/委托的 scope 授权 测试(MCP-SP §2.10)。"""

import json

from agentgate.gateway import Gateway
from agentgate.policy import Policy
from agentgate.identity import Identity, Principal


def _gw(tmp_path, policy):
    return Gateway(policy=policy, audit_path=str(tmp_path / "a.ndjson"),
                   trace_path=str(tmp_path / "t.ndjson"))


def test_effective_grants_attenuation():
    # agent 自身有 {a,b}，代表 user(有 {b,c}) -> 有效授权 = 交集 {b}
    ident = Identity(Principal("agent", "agent", frozenset({"a", "b"})),
                     on_behalf_of=[Principal("user-42", "user", frozenset({"b", "c"}))])
    assert ident.effective_grants() == frozenset({"b"})
    assert ident.subject == "user-42"        # 最终代表的主体
    assert ident.chain()[0].id == "agent"


def test_scope_authz_allows_when_granted(tmp_path):
    policy = Policy(tool_scopes={"read_customer": {"read:customer"}})
    gw = _gw(tmp_path, policy)
    ident = Identity(Principal("agent", "agent", frozenset({"read:customer"})))
    r = gw.call("read_customer", {"id": 1}, handler=lambda i: "ok", principal=ident)
    assert r.decision == "allow"


def test_scope_authz_blocks_when_missing(tmp_path):
    policy = Policy(tool_scopes={"issue_refund": {"refund:create"}})
    gw = _gw(tmp_path, policy)
    ident = Identity(Principal("agent", "agent", frozenset({"read:customer"})))
    r = gw.call("issue_refund", {"amt": 10}, handler=lambda i: "done", principal=ident)
    assert r.decision == "block"
    assert "refund:create" in " ".join(r.reasons)


def test_delegation_attenuation_blocks_overreach(tmp_path):
    # agent 自己被授予 refund:create，但它代表的 user 没有 -> 衰减后无权 -> 拦截
    policy = Policy(tool_scopes={"issue_refund": {"refund:create"}})
    gw = _gw(tmp_path, policy)
    ident = Identity(Principal("agent", "agent", frozenset({"refund:create"})),
                     on_behalf_of=[Principal("user-42", "user", frozenset({"read:customer"}))])
    r = gw.call("issue_refund", {"amt": 10}, handler=lambda i: "done", principal=ident)
    assert r.decision == "block"
    assert "user-42" in " ".join(r.reasons)      # 报清楚是替谁做事时越权


def test_scope_required_but_no_identity_blocks(tmp_path):
    policy = Policy(tool_scopes={"issue_refund": {"refund:create"}})
    gw = _gw(tmp_path, policy)
    r = gw.call("issue_refund", {"amt": 10}, handler=lambda i: "x", principal="plain-string")
    assert r.decision == "block"
    assert "no identity" in " ".join(r.reasons).lower()


def test_audit_records_subject_and_delegation(tmp_path):
    audit = str(tmp_path / "a.ndjson")
    gw = Gateway(policy=Policy(), audit_path=audit, trace_path=str(tmp_path / "t.ndjson"))
    ident = Identity(Principal("agent", "agent", frozenset({"read:customer"})),
                     on_behalf_of=[Principal("user-42", "user", frozenset({"read:customer"}))])
    gw.call("read_customer", {"id": 1}, handler=lambda i: "ok", principal=ident)
    rec = json.loads(open(audit, encoding="utf-8").read().splitlines()[0])
    assert rec["principal"] == "agent"           # 旧字段仍是发起者 id
    assert rec["identity"]["subject"] == "user-42"
    assert rec["identity"]["delegation"] == ["agent", "user-42"]
    assert rec["identity"]["granted"] == ["read:customer"]


def test_backward_compat_string_principal_unchanged(tmp_path):
    """字符串 principal：审计记录不应出现 identity 字段(与旧版逐字节兼容)。"""
    audit = str(tmp_path / "a.ndjson")
    gw = Gateway(policy=Policy(), audit_path=audit, trace_path=str(tmp_path / "t.ndjson"))
    gw.call("read", {"x": 1}, handler=lambda i: "ok", principal="agent-csr")
    rec = json.loads(open(audit, encoding="utf-8").read().splitlines()[0])
    assert rec["principal"] == "agent-csr"
    assert "identity" not in rec                  # 无身份上下文 -> 无该字段
    # 且链仍可校验
    from agentgate.audit import AuditLog
    ok, _ = AuditLog(audit).verify()
    assert ok


def test_three_hop_delegation_attenuation(tmp_path):
    """service → agent → user 三级委托：有效授权 = 三者 grants 的交集。"""
    from agentgate.identity import Identity, Principal

    ident = Identity(
        Principal("service-plat", "service", frozenset({"read:customer", "refund:create", "admin"})),
        on_behalf_of=[
            Principal("agent-csr", "agent", frozenset({"read:customer", "refund:create"})),
            Principal("user-42", "user", frozenset({"read:customer"})),
        ],
    )
    assert ident.subject == "user-42"
    assert ident.chain()[0].id == "service-plat"
    assert ident.effective_grants() == frozenset({"read:customer"})

    policy = Policy(tool_scopes={"read_customer": {"read:customer"},
                                 "issue_refund": {"refund:create"}})
    gw = _gw(tmp_path, policy)
    r1 = gw.call("read_customer", {"id": 1}, handler=lambda i: "ok", principal=ident)
    assert r1.decision == "allow"
    r2 = gw.call("issue_refund", {"amt": 10}, handler=lambda i: "x", principal=ident)
    assert r2.decision == "block"
    assert "refund:create" in " ".join(r2.reasons)


def test_audit_three_hop_delegation_chain(tmp_path):
    """三级委托链完整写入审计 identity.delegation。"""
    import json
    from agentgate.identity import Identity, Principal

    audit = str(tmp_path / "a.ndjson")
    gw = Gateway(policy=Policy(), audit_path=audit,
                 trace_path=str(tmp_path / "t.ndjson"))
    ident = Identity(
        Principal("service-plat", "service", frozenset({"read:customer"})),
        on_behalf_of=[
            Principal("agent-csr", "agent", frozenset({"read:customer"})),
            Principal("user-42", "user", frozenset({"read:customer"})),
        ],
    )
    gw.call("read", {"x": 1}, handler=lambda i: "ok", principal=ident)
    rec = json.loads(open(audit, encoding="utf-8").read().splitlines()[0])
    assert rec["identity"]["delegation"] == ["service-plat", "agent-csr", "user-42"]
    assert rec["identity"]["subject"] == "user-42"
    assert rec["identity"]["actor"] == "service-plat"


def test_policy_from_dict_loads_tool_scopes():
    p = Policy.from_dict({"tool_scopes": {"issue_refund": ["refund:create"]}})
    assert p.tool_scopes["issue_refund"] == {"refund:create"}
