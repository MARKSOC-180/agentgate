"""
anchoring.py —— 审计链外部锚定(让连管理员都无法神不知鬼不觉改历史)。

哈希链能挡住「随手改一行」，但挡不住一个拥有写权限、且知道哈希算法的管理员：
他可以改掉一条记录，再把整条链从那条往后全部重算，verify() 就会重新通过。

锚定解决这个终局问题：周期性地把「链尖哈希 + 记录数 + 时间」作为一个**锚点**，
推到一个**独立的、最好是外部不可变 / 第三方时间戳**的去处(webhook、对象存储、
公链、甚至打印到集中式日志)。之后，谁要改历史，就必须同时改掉所有外部锚点——
而那些锚点不在他的控制范围内。

本模块：
  - Anchor.anchor(audit)        生成并持久化一个锚点(锚点之间也哈希成链)
  - Anchor.verify(audit)        用锚点反查审计链：任一历史锚点对不上 = 被重写
  - sink 回调                    可把锚点同步推到外部(webhook/命令/stdout)，零依赖

纯标准库。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Callable, Optional

from .audit import AuditLog


def _hash(prev: str, body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256((prev + "|" + canonical).encode("utf-8")).hexdigest()


class Anchor:
    def __init__(self, path: str = "agentgate_anchors.ndjson",
                 sink: Optional[Callable[[dict], None]] = None):
        self.path = path
        self.sink = sink            # 可选：把锚点推到外部(webhook/命令/集中日志)
        self._lock = threading.Lock()
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)

    def _last_anchor_hash(self) -> str:
        last = "ANCHOR_GENESIS"
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            last = json.loads(line).get("anchor_hash", last)
                        except Exception:
                            pass
        return last

    def anchor(self, audit: AuditLog) -> dict:
        """对审计链当前状态打一个锚点，持久化并(可选)推到外部 sink。"""
        with self._lock:
            head, count = audit.head()
            prev = self._last_anchor_hash()
            body = {
                "ts": time.time(),
                "count": count,          # 此刻审计链有多少条记录
                "audit_head": head,      # 此刻审计链尖哈希
                "prev_anchor": prev,
            }
            anchor_hash = _hash(prev, body)
            rec = {**body, "anchor_hash": anchor_hash}
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        if self.sink:
            try:
                self.sink(rec)
            except Exception:
                pass
        return rec

    def records(self) -> list:
        out = []
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        out.append(json.loads(line))
        return out

    def verify_anchor_chain(self) -> tuple:
        """校验锚点文件自身是否完好(锚点之间也是哈希链)。"""
        prev = "ANCHOR_GENESIS"
        n = 0
        for i, rec in enumerate(self.records(), 1):
            body = {k: v for k, v in rec.items() if k != "anchor_hash"}
            if body.get("prev_anchor") != prev:
                return False, f"anchor #{i}: broken anchor chain (prev mismatch)"
            if _hash(prev, body) != rec.get("anchor_hash"):
                return False, f"anchor #{i}: anchor hash mismatch (tampered)"
            prev = rec["anchor_hash"]
            n += 1
        return True, f"anchor chain intact, {n} anchors"

    def verify(self, audit: AuditLog) -> tuple:
        """用锚点反查审计链。

        逻辑：对每个历史锚点，审计链在「第 count 条」处的链尖哈希必须等于锚点记录的
        audit_head。若有人重写了历史并重算整条链，这些历史链尖会改变，与锚点不符。
        """
        anchors = self.records()
        if not anchors:
            return True, "no anchors recorded"

        ok_chain, msg_chain = self.verify_anchor_chain()
        if not ok_chain:
            return False, msg_chain

        records = audit.load()
        running = [r.get("this_hash") for r in records]   # 第 k 条之后的链尖
        for i, a in enumerate(anchors, 1):
            count = a.get("count", 0)
            if count == 0:
                continue
            if count > len(running):
                return False, (f"anchor #{i} expects >= {count} audit records "
                               f"but found {len(running)} (records deleted/truncated)")
            actual_head = running[count - 1]
            if actual_head != a.get("audit_head"):
                return False, (f"anchor #{i} (count={count}): audit head changed "
                               f"since anchoring — history was rewritten")
        return True, f"verified against {len(anchors)} anchor(s); history intact"
