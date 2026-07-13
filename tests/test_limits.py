"""limits.py 的单元测试：配额与限流。"""

from agentgate.limits import Limiter, RateLimit


def test_rate_limit_window():
    lim = Limiter(default_rate=RateLimit(max_calls=2, window=60))
    assert lim.check("t", "u") is None
    lim.commit("t", "u")
    assert lim.check("t", "u") is None
    lim.commit("t", "u")
    # 窗口内已 2 次，第 3 次应被限
    assert lim.check("t", "u") is not None


def test_per_tool_override():
    lim = Limiter(default_rate=RateLimit(100, 60), per_tool={"refund": RateLimit(1, 60)})
    lim.commit("refund", "u")
    assert lim.check("refund", "u") is not None
    assert lim.check("other", "u") is None


def test_total_budget():
    lim = Limiter(max_calls_total=2)
    lim.commit("a", "u"); lim.commit("b", "u")
    assert "budget" in (lim.check("c", "u") or "").lower()


def test_per_principal_budget():
    lim = Limiter(max_calls_per_principal=1)
    lim.commit("a", "alice")
    assert lim.check("b", "alice") is not None
    assert lim.check("b", "bob") is None


def test_cost_budget():
    lim = Limiter(max_cost=10.0)
    lim.commit("a", "u", cost=8.0)
    assert lim.check("b", "u", cost=5.0) is not None   # 8+5 > 10
    assert lim.check("b", "u", cost=1.0) is None        # 8+1 <= 10


def test_from_dict():
    lim = Limiter.from_dict({
        "default_rate": {"max_calls": 10, "window": 30},
        "per_tool": {"refund": {"max_calls": 1, "window": 60}},
        "max_cost": 50,
    })
    assert lim.default_rate.max_calls == 10
    assert lim.per_tool["refund"].max_calls == 1
    assert lim.max_cost == 50
