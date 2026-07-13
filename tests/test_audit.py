"""audit.py 的单元测试：哈希链不可篡改审计。"""

import json

from agentgate.audit import AuditLog, digest


def _append(log, tool="t", decision="allow"):
    log.append(tool=tool, principal="u", decision=decision, reasons=[],
               redaction_hits={}, safety=[], input_digest="a",
               output_digest="b", duration_ms=1.0)


def test_empty_chain_verifies(tmp_path):
    log = AuditLog(str(tmp_path / "a.ndjson"))
    ok, _ = log.verify()
    assert ok


def test_chain_verifies_after_appends(tmp_path):
    log = AuditLog(str(tmp_path / "a.ndjson"))
    for _ in range(5):
        _append(log)
    ok, msg = log.verify()
    assert ok
    assert "5" in msg


def test_tamper_is_detected(tmp_path):
    path = tmp_path / "a.ndjson"
    log = AuditLog(str(path))
    for _ in range(3):
        _append(log)
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["decision"] = "block"  # 偷偷改第二条
    lines[1] = json.dumps(rec, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, msg = log.verify()
    assert not ok
    assert "2" in msg


def test_deletion_is_detected(tmp_path):
    path = tmp_path / "a.ndjson"
    log = AuditLog(str(path))
    for _ in range(3):
        _append(log)
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # 删掉中间一条 → 断链
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, _ = log.verify()
    assert not ok


def test_digest_is_deterministic():
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})
