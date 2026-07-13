"""PrincipalResolver 插件钩子测试。"""

from agentgate.identity import (
    Identity, Principal, PrincipalResolver, register_resolver, resolve_token,
)


class _FakeResolver(PrincipalResolver):
    def resolve(self, token: str):
        if token == "good":
            return Identity(Principal("user-1", "user", frozenset({"read:x"})))
        return None


def test_resolve_token_with_registered_resolver():
    register_resolver(_FakeResolver())
    ident = resolve_token("good")
    assert ident is not None
    assert ident.subject == "user-1"
    assert resolve_token("bad") is None
