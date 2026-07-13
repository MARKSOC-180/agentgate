"""
limits.py —— 配额与限流(防 agent 失控烧钱 / 刷爆下游 API)。

一个失控或被劫持的 agent，最现实的伤害不是"说错话"，而是：
在几秒内把某个工具调用上千次、把下游 API 配额烧光、把账单打爆。
这一层在「策略放行之后、执行之前」再加一道闸：

  - 滑动窗口限流：每个 (principal, tool) 在 N 秒内最多 M 次
  - 调用预算：每个 principal(或全局)累计调用次数上限
  - 成本预算：累计成本上限(按调用方传入的 cost 估算)

纯内存 + 标准库，确定性、零依赖。超限即返回拦截原因，交给 gateway 拦下。
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RateLimit:
    """滑动窗口限流：window 秒内最多 max_calls 次。"""
    max_calls: int
    window: float = 60.0


@dataclass
class Limiter:
    """
    可声明的配额/限流。任一维度超限即拦截。

        limiter = Limiter(
            default_rate=RateLimit(max_calls=60, window=60),       # 每个工具默认 60 次/分
            per_tool={"issue_refund": RateLimit(5, 60)},           # 退款更严
            max_calls_per_principal=1000,                          # 单 principal 调用预算
            max_cost=50.0,                                         # 累计成本预算(美元)
        )
    """
    default_rate: Optional[RateLimit] = None
    per_tool: dict = field(default_factory=dict)            # tool -> RateLimit
    per_principal_rate: dict = field(default_factory=dict)  # principal -> RateLimit
    max_calls_per_principal: Optional[int] = None
    max_calls_total: Optional[int] = None
    max_cost: Optional[float] = None

    def __post_init__(self):
        self._lock = threading.Lock()
        self._events: dict = defaultdict(deque)     # key -> 时间戳队列(滑动窗口)
        self._calls_by_principal: dict = defaultdict(int)
        self._calls_total = 0
        self._cost_total = 0.0

    @classmethod
    def from_dict(cls, data: dict) -> "Limiter":
        if not data:
            return cls()

        def _rl(d):
            return RateLimit(int(d["max_calls"]), float(d.get("window", 60.0))) if d else None

        return cls(
            default_rate=_rl(data.get("default_rate")),
            per_tool={k: _rl(v) for k, v in (data.get("per_tool") or {}).items()},
            per_principal_rate={k: _rl(v) for k, v in (data.get("per_principal_rate") or {}).items()},
            max_calls_per_principal=data.get("max_calls_per_principal"),
            max_calls_total=data.get("max_calls_total"),
            max_cost=data.get("max_cost"),
        )

    def _window_exceeded(self, key, rl: RateLimit, now: float) -> bool:
        q = self._events[key]
        cutoff = now - rl.window
        while q and q[0] < cutoff:
            q.popleft()
        # 注意：此处只判断，不记录；真正计数在 commit() 里发生
        return len(q) >= rl.max_calls

    def check(self, tool: str, principal: Optional[str], cost: float = 0.0) -> Optional[str]:
        """执行前判定。返回 None 表示放行；返回字符串表示超限原因(拦截)。"""
        now = time.time()
        principal = principal or "<anon>"
        with self._lock:
            if self.max_calls_total is not None and self._calls_total >= self.max_calls_total:
                return f"Global call budget reached ({self.max_calls_total} calls)"
            if (self.max_calls_per_principal is not None and
                    self._calls_by_principal[principal] >= self.max_calls_per_principal):
                return (f"Principal `{principal}` reached its call budget "
                        f"({self.max_calls_per_principal} calls)")
            if self.max_cost is not None and (self._cost_total + cost) > self.max_cost:
                return f"Would exceed cost budget (${self.max_cost})"

            rl_tool = self.per_tool.get(tool, self.default_rate)
            if rl_tool and self._window_exceeded(("tool", tool), rl_tool, now):
                return (f"Tool `{tool}` is rate-limited "
                        f"({rl_tool.max_calls}/{rl_tool.window:g}s)")
            rl_pr = self.per_principal_rate.get(principal)
            if rl_pr and self._window_exceeded(("principal", principal), rl_pr, now):
                return (f"Principal `{principal}` is rate-limited "
                        f"({rl_pr.max_calls}/{rl_pr.window:g}s)")
        return None

    def commit(self, tool: str, principal: Optional[str], cost: float = 0.0) -> None:
        """放行并执行后调用：把这次调用计入窗口与预算。"""
        now = time.time()
        principal = principal or "<anon>"
        with self._lock:
            self._events[("tool", tool)].append(now)
            self._events[("principal", principal)].append(now)
            self._calls_by_principal[principal] += 1
            self._calls_total += 1
            self._cost_total += cost
