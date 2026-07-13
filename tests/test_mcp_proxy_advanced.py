"""MCP 代理高级路径：identity / limits / approval 审计字段。"""

import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOCK = os.path.join(REPO_ROOT, "mock_mcp_server.py")


def _rpc(proc, msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def test_proxy_identity_and_limits_in_audit(tmp_path):
    cfg = {
        "command": [sys.executable, MOCK],
        "audit_path": str(tmp_path / "audit.ndjson"),
        "trace_path": str(tmp_path / "trace.ndjson"),
        "identity": {
            "principal": {"id": "agent", "type": "agent", "grants": ["read:customer"]},
            "on_behalf_of": [{"id": "user-1", "type": "user", "grants": ["read:customer"]}],
        },
        "limits": {"max_calls_total": 100},
        "policy": {
            "require_approval_tools": ["delete_records"],
            "destructive_tools": ["delete_records"],
        },
        "approvals_path": str(tmp_path / "approvals.json"),
    }
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")

    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate.mcp_proxy", "--config", str(p)],
        cwd=REPO_ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
    )
    try:
        _rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        _rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "read_customer_record", "arguments": {"customer_id": "c"}}})
        _rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "delete_records", "arguments": {"table": "t"}}})
    finally:
        proc.stdin.close()
        proc.wait(timeout=15)

    lines = open(tmp_path / "audit.ndjson", encoding="utf-8").read().splitlines()
    assert len(lines) == 2
    allow_rec = json.loads(lines[0])
    block_rec = json.loads(lines[1])
    assert allow_rec.get("identity", {}).get("subject") == "user-1"
    assert allow_rec.get("limits", {}).get("checked") is True
    assert block_rec.get("approval", {}).get("status") == "pending"


def test_proxy_approval_approve_and_retry(tmp_path):
    """人在环：pending → approve → 带 _approval_id 重试放行。"""
    cfg = {
        "command": [sys.executable, MOCK],
        "audit_path": str(tmp_path / "audit.ndjson"),
        "trace_path": str(tmp_path / "trace.ndjson"),
        "policy": {
            "require_approval_tools": ["delete_records"],
            "destructive_tools": ["delete_records"],
        },
        "approvals_path": str(tmp_path / "approvals.json"),
    }
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")

    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate.mcp_proxy", "--config", str(p)],
        cwd=REPO_ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
    )
    try:
        _rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        blocked = _rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                              "params": {"name": "delete_records", "arguments": {"table": "t"}}})
        assert blocked.get("result", {}).get("isError") or "error" in str(blocked).lower()

        from agentgate.approvals import ApprovalStore
        pending = ApprovalStore(str(tmp_path / "approvals.json")).pending()
        assert len(pending) == 1
        aid = pending[0]["id"]
        ApprovalStore(str(tmp_path / "approvals.json")).approve(aid)

        ok = _rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "delete_records",
                                    "arguments": {"table": "t", "_approval_id": aid}}})
        assert not ok.get("result", {}).get("isError", True)
    finally:
        proc.stdin.close()
        proc.wait(timeout=15)

    lines = open(tmp_path / "audit.ndjson", encoding="utf-8").read().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["approval"]["status"] == "pending"
    assert json.loads(lines[1])["approval"]["status"] == "approved"
    assert json.loads(lines[1])["decision"] == "allow"
