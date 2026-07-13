"""
approvals.py —— 人在环审批(Human-in-the-loop)。

某些操作不该「自动允许」也不该「直接拒绝」，而应该「停下来等人点头」：
退大额款、删生产数据、改权限……这正是 EU AI Act Art.14「人类监督」、
以及 SOC2 变更管理要的闸门。

机制：被标记为需审批的工具，首次调用不执行，而是登记一条 pending 审批请求，
返回一个 approval_id 并拦截。人类用 CLI(或 API)approve / deny 之后，
agent 带着这个已批准的 approval_id 再调用一次，才放行。

本地 JSON 持久化、append 审计友好、零依赖。
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from typing import Optional

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"


class ApprovalStore:
    def __init__(self, path: str = "agentgate_approvals.json"):
        self.path = path
        self._lock = threading.Lock()
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception:
                return {}

    def _save(self, data: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        os.replace(tmp, self.path)

    def request(self, tool: str, principal: Optional[str], reason: str = "",
                input_digest: str = "") -> str:
        """登记一条待审批请求，返回 approval_id。"""
        with self._lock:
            data = self._load()
            aid = uuid.uuid4().hex[:12]
            data[aid] = {
                "id": aid, "tool": tool, "principal": principal,
                "reason": reason, "input_digest": input_digest,
                "status": PENDING, "created_at": time.time(),
                "decided_at": None, "approver": None,
            }
            self._save(data)
            return aid

    def _decide(self, approval_id: str, status: str, approver: Optional[str]) -> bool:
        with self._lock:
            data = self._load()
            rec = data.get(approval_id)
            if not rec or rec["status"] != PENDING:
                return False
            rec["status"] = status
            rec["approver"] = approver
            rec["decided_at"] = time.time()
            self._save(data)
            return True

    def approve(self, approval_id: str, approver: str = "human") -> bool:
        return self._decide(approval_id, APPROVED, approver)

    def deny(self, approval_id: str, approver: str = "human") -> bool:
        return self._decide(approval_id, DENIED, approver)

    def get(self, approval_id: str) -> Optional[dict]:
        return self._load().get(approval_id)

    def status(self, approval_id: str) -> Optional[str]:
        rec = self.get(approval_id)
        return rec["status"] if rec else None

    def pending(self) -> list:
        return [r for r in self._load().values() if r["status"] == PENDING]

    def all(self) -> list:
        return sorted(self._load().values(), key=lambda r: r.get("created_at", 0))
