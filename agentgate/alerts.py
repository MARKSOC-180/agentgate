"""
alerts.py —— 实时告警(拦截 / 高危时立刻通知)。

控制平面拦下了一次越权删库，但没人知道——等于没拦。
这一层在「决策落定」后，对满足条件的事件(默认：被拦截 或 critical 安全发现)
触发告警，支持两种零依赖通道：

  - command：执行一条本地命令(事件 JSON 经 stdin 传入)，可对接任意脚本/IM 机器人
  - webhook：HTTP POST 事件 JSON(标准库 urllib，可对接 Slack/飞书/PagerDuty 等)

告警失败绝不影响主流程(best-effort，异常吞掉并记到 stderr)。
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Alerter:
    """
        alerter = Alerter(
            webhook="https://hooks.slack.com/services/XXX",
            command=None,
            on=("block", "critical"),   # 触发条件
        )
    """
    webhook: Optional[str] = None
    command: Optional[list] = None          # 例如 ["python", "notify.py"]
    on: tuple = ("block", "critical")
    timeout: float = 5.0
    _sent: list = field(default_factory=list, repr=False)  # 便于测试/自省

    @classmethod
    def from_dict(cls, data: dict) -> "Alerter":
        if not data:
            return cls(on=())
        cmd = data.get("command")
        if isinstance(cmd, str):
            import shlex
            cmd = shlex.split(cmd)
        return cls(
            webhook=data.get("webhook"),
            command=cmd,
            on=tuple(data.get("on", ("block", "critical"))),
            timeout=float(data.get("timeout", 5.0)),
        )

    def should_fire(self, decision: str, max_sev: Optional[str]) -> bool:
        if "block" in self.on and decision == "block":
            return True
        if max_sev and max_sev in self.on:
            return True
        return False

    def notify(self, event: dict) -> bool:
        """发送告警。返回是否至少成功投递一个通道。best-effort。"""
        payload = json.dumps(event, ensure_ascii=False, default=str)
        self._sent.append(event)
        ok = False
        if self.command:
            try:
                subprocess.run(self.command, input=payload, text=True,
                               timeout=self.timeout, check=False)
                ok = True
            except Exception as e:  # noqa: BLE001
                sys.stderr.write(f"[AgentGate] alert command failed: {e}\n")
        if self.webhook:
            try:
                req = urllib.request.Request(
                    self.webhook, data=payload.encode("utf-8"),
                    headers={"Content-Type": "application/json"}, method="POST")
                urllib.request.urlopen(req, timeout=self.timeout)  # noqa: S310
                ok = True
            except Exception as e:  # noqa: BLE001
                sys.stderr.write(f"[AgentGate] alert webhook failed: {e}\n")
        return ok
