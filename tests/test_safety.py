"""safety.py 的单元测试：危险动作检测。"""

from agentgate.safety import scan_safety, max_severity


def test_delete_without_where_is_critical():
    f = scan_safety("run_sql", {"sql": "DELETE FROM users"})
    assert any(x.severity == "critical" for x in f)


def test_delete_with_where_is_safe():
    f = scan_safety("run_sql", {"sql": "DELETE FROM users WHERE id=1"})
    assert not any(x.title == "无条件批量删除" for x in f)


def test_rm_rf_is_critical():
    f = scan_safety("shell", {"cmd": "rm -rf /"})
    assert any(x.severity == "critical" for x in f)


def test_large_amount_is_high():
    f = scan_safety("issue_refund", {"amount": 40000})
    assert any(x.severity == "high" and "money" in x.title.lower() for x in f)


def test_ssrf_metadata_endpoint():
    f = scan_safety("fetch", {"url": "http://169.254.169.254/latest/meta-data"})
    assert any("SSRF" in x.title for x in f)


def test_max_severity_ordering():
    f = scan_safety("run_sql", {"sql": "DELETE FROM t", "amount": 99999})
    assert max_severity(f) == "critical"
    assert max_severity([]) is None
