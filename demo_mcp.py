"""
demo_mcp.py —— MCP 代理端到端演示(真起子进程，非 mock 内部调用)。

它会：
  1. 以子进程方式启动 `python -m agentgate.mcp_proxy --config agentgate.config.json`
     ——代理内部再拉起 mock_mcp_server.py 作为「下游真实 MCP server」。
  2. 像一个 MCP host(Cursor/Claude Desktop)那样，通过 stdio 发 JSON-RPC：
        initialize → tools/list → 四次 tools/call
  3. 展示控制平面的真实效果：
        - read_customer_record：放行，但返回里的 API 密钥/邮箱被「脱敏后」才回传
        - delete_records：被拦截(需授权 + 破坏性，未预授权)，绝不触达下游
        - issue_refund：被拦截(破坏性，未授权)
        - web_search：放行
  4. 最后生成合规包(Markdown + CSV)与 HTML 报告。

这就是给买家看的「不改一行代码，挡在任意 MCP server 前面」的 5 分钟 aha。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
AUDIT = os.path.join(HERE, "agentgate_audit.ndjson")
TRACE = os.path.join(HERE, "agentgate_trace.ndjson")


def _fresh():
    for p in (AUDIT, TRACE):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


def _send(proc, msg):
    proc.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
    proc.stdin.flush()


def _recv(proc):
    line = proc.stdout.readline()
    return json.loads(line) if line.strip() else None


def _call(proc, rpc_id, name, arguments):
    _send(proc, {"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
                 "params": {"name": name, "arguments": arguments}})
    resp = _recv(proc)
    result = (resp or {}).get("result", {})
    is_err = result.get("isError", False)
    text = ""
    for item in result.get("content", []) or []:
        if isinstance(item, dict) and item.get("type") == "text":
            text = item.get("text", "")
            break
    tag = "⛔ BLOCKED" if is_err else "✅ ALLOWED"
    print(f"\n  [{rpc_id}] tools/call {name}({arguments})")
    print(f"      {tag}")
    print(f"      → {text}")


def main():
    _fresh()
    print("=" * 70)
    print("  AgentGate · MCP 代理端到端演示")
    print("  上游(本脚本) → [AgentGate 代理] → 下游(mock_mcp_server.py)")
    print("=" * 70)

    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate.mcp_proxy", "--config", "agentgate.config.json"],
        cwd=HERE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=sys.stderr, text=True, encoding="utf-8", bufsize=1,
    )
    time.sleep(0.3)

    # 1. 握手
    _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    init = _recv(proc)
    print(f"\n  initialize → server: {init['result']['serverInfo']['name']}")

    # 2. 列工具(透明转发)
    _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tl = _recv(proc)
    names = [t["name"] for t in tl["result"]["tools"]]
    print(f"  tools/list → {names}")

    # 3. 四次真实调用
    _call(proc, 3, "read_customer_record", {"customer_id": "c-204"})  # 放行 + 脱敏
    _call(proc, 4, "delete_records", {"table": "orders", "where": ""})  # 拦截
    _call(proc, 5, "issue_refund", {"order": "o-99", "amount": 40000})  # 拦截
    _call(proc, 6, "web_search", {"q": "mcp security"})                 # 放行

    proc.stdin.close()
    proc.wait(timeout=5)

    # 4. 合规包 + HTML 报告
    print("\n" + "=" * 70)
    from agentgate.compliance import export_compliance
    from agentgate.report import build_report
    from agentgate.audit import AuditLog

    info = export_compliance(AUDIT, out_dir=os.path.join(HERE, "compliance_export"))
    ok, msg = AuditLog(AUDIT).verify()
    report_html = os.path.join(HERE, "agentgate_report.html")
    build_report(AUDIT, report_html)

    print(f"  审计链校验：{'PASS ✅' if ok else 'FAIL ❌'} — {msg}")
    print(f"  调用总数 {info['total']}｜放行 {info['allowed']}｜拦截 {info['blocked']}"
          f"｜脱敏命中 {info['redaction_total']}")
    print(f"  合规报告：{info['report_path']}")
    print(f"  审计 CSV ：{info['csv_path']}")
    print(f"  HTML 报告：{report_html}")
    print("=" * 70)


if __name__ == "__main__":
    main()
