"""alerts.py 的单元测试：实时告警。"""

import sys

from agentgate.alerts import Alerter


def test_should_fire_on_block():
    a = Alerter(on=("block", "critical"))
    assert a.should_fire("block", None) is True
    assert a.should_fire("allow", None) is False


def test_should_fire_on_severity():
    a = Alerter(on=("block", "critical"))
    assert a.should_fire("allow", "critical") is True
    assert a.should_fire("allow", "warning") is False


def test_notify_via_command_records_event():
    # 用一个读 stdin 即退出的命令，确保跨平台可用
    a = Alerter(command=[sys.executable, "-c", "import sys; sys.stdin.read()"])
    ok = a.notify({"tool": "x", "decision": "block"})
    assert ok is True
    assert a._sent and a._sent[-1]["tool"] == "x"


def test_notify_no_channel_is_best_effort():
    a = Alerter()  # 无 command/webhook
    assert a.notify({"tool": "x"}) is False
    assert len(a._sent) == 1


def test_from_dict():
    a = Alerter.from_dict({"webhook": "http://example.com/h", "on": ["block"]})
    assert a.webhook == "http://example.com/h"
    assert a.on == ("block",)
