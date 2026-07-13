"""mcp_proxy.py 的端到端测试：真起代理子进程，挡在 mock MCP server 前。"""

import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOCK = os.path.join(REPO_ROOT, "mock_mcp_server.py")


def _write_config(tmp_path):
    cfg = {
        # command 用列表，避免 Windows 路径里的反斜杠被 shlex 吃掉
        "command": [sys.executable, MOCK],
        "principal": "test-client",
        "pre_authorized_tools": ["read_customer_record"],
        "policy": {
            "require_auth_tools": ["delete_records"],
            "destructive_tools": ["delete_records"],
            "allow_destructive": False,
        },
        "audit_path": str(tmp_path / "audit.ndjson"),
        "trace_path": str(tmp_path / "trace.ndjson"),
    }
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return str(p)


def _rpc(proc, msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def _call(proc, rpc_id, name, args):
    return _rpc(proc, {"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
                       "params": {"name": name, "arguments": args}})


def test_proxy_allows_blocks_and_redacts(tmp_path):
    cfg = _write_config(tmp_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate.mcp_proxy", "--config", cfg],
        cwd=REPO_ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
    )
    try:
        init = _rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert init["result"]["serverInfo"]["name"] == "mock-mcp-server"
        mcp_sp = (init["result"].get("capabilities") or {}).get("experimental", {}).get("mcp-sp")
        assert mcp_sp and mcp_sp.get("level") == 3

        # 放行 + 脱敏：返回里的密钥/邮箱不应原样出现
        r = _call(proc, 2, "read_customer_record", {"customer_id": "c-1"})
        text = r["result"]["content"][0]["text"]
        assert r["result"].get("isError") in (False, None)
        assert "jane.doe@example.com" not in text
        assert "sk-live-AbCdEf0123456789ZyXwVu98765432" not in text

        # 拦截：未授权的破坏性工具，绝不触达下游
        b = _call(proc, 3, "delete_records", {"table": "orders", "where": ""})
        assert b["result"]["isError"] is True
        assert "AgentGate blocked" in b["result"]["content"][0]["text"]
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)

    # 审计链应记录两次调用且完好
    from agentgate.audit import AuditLog
    log = AuditLog(str(tmp_path / "audit.ndjson"))
    ok, _ = log.verify()
    assert ok
    assert len(log.load()) == 2
