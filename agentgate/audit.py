"""
audit.py —— 不可篡改的审计日志(哈希链)。

每一次工具调用都追加一条审计记录，且每条记录都包含「上一条记录的哈希」，
形成一条哈希链。任何人事后偷偷修改/删除/插入一条记录，链就会断——
verify() 能立刻发现。这是 SOC2 / GDPR / AI Act 审计要的「不可抵赖」证据，
而且完全本地、append-only、零外部依赖。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time


class AuditLog:
    def __init__(self, path: str = "agentgate_audit.ndjson"):
        self.path = path
        self._lock = threading.Lock()
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)

    def _last_hash(self) -> str:
        """读取链上最后一条记录的哈希，作为新记录的 prev_hash。"""
        last = "GENESIS"
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            last = json.loads(line).get("this_hash", last)
                        except Exception:
                            pass
        return last

    @staticmethod
    def _hash(prev_hash: str, body: dict) -> str:
        canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256((prev_hash + "|" + canonical).encode("utf-8")).hexdigest()

    def append(self, *, tool: str, principal, decision: str, reasons,
               redaction_hits: dict, safety: list, input_digest: str,
               output_digest: str, duration_ms: float, identity: dict = None,
               limits: dict = None, approval: dict = None) -> dict:
        """追加一条审计记录，返回该记录。

        identity / limits / approval 均为可选 MCP-SP 扩展；为 None 时记录与旧版逐字节一致，
        以保证向后兼容(不破坏既有哈希链、测试与一致性向量)。
        """
        with self._lock:
            prev = self._last_hash()
            body = {
                "ts": time.time(),
                "tool": tool,
                "principal": principal,
                "decision": decision,            # allow / block
                "reasons": list(reasons or []),
                "redaction_hits": dict(redaction_hits or {}),
                "safety": [f"{s.severity}:{s.title}" for s in (safety or [])],
                "input_sha256": input_digest,
                "output_sha256": output_digest,
                "duration_ms": round(duration_ms, 3),
                "prev_hash": prev,
            }
            if identity is not None:
                body["identity"] = identity
            if limits is not None:
                body["limits"] = limits
            if approval is not None:
                body["approval"] = approval
            this_hash = self._hash(prev, body)
            record = {**body, "this_hash": this_hash}
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            return record

    def verify(self) -> tuple[bool, str]:
        """校验整条链是否完好。返回 (是否完好, 说明)。"""
        prev = "GENESIS"
        n = 0
        if not os.path.exists(self.path):
            return True, "audit log is empty"
        with open(self.path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                claimed = rec.get("this_hash")
                body = {k: v for k, v in rec.items() if k != "this_hash"}
                if body.get("prev_hash") != prev:
                    return False, f"record #{i}: prev_hash does not match the chain (deleted/inserted?)"
                # 用与 append 完全相同的方式重算：哈希覆盖含 prev_hash 的整个 body
                recomputed = self._hash(prev, body)
                if recomputed != claimed:
                    return False, f"record #{i}: hash mismatch (tampered?)"
                prev = claimed
                n += 1
        return True, f"chain intact, {n} records, no tampering"

    def head(self) -> tuple:
        """返回链尖 (last_hash, count)：当前最后一条记录的哈希与记录总数。

        这是「外部锚定」的锚点——把它定期推到独立/不可变存储后，
        即便有人拥有写权限、能改审计文件并重算整条链，也无法让历史锚点重新对上。
        """
        last = "GENESIS"
        n = 0
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            last = json.loads(line).get("this_hash", last)
                            n += 1
                        except Exception:
                            pass
        return last, n

    def load(self) -> list:
        out = []
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        out.append(json.loads(line))
        return out


def digest(value) -> str:
    """对任意内容算 SHA256(用于审计记录中证明输入/输出的完整性，但不存明文)。"""
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
