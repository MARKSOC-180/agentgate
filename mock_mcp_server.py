"""
mock_mcp_server.py —— 一个极简的「下游真实 MCP server」(仅用于演示)。

它实现 MCP stdio 传输的最小子集：按行读 JSON-RPC，按行回 JSON-RPC。
支持 initialize / tools/list / tools/call 三类方法。

关键演示点：`read_customer_record` 的返回里故意混入了 API 密钥与邮箱，
用来证明 AgentGate 代理会在「数据流回上游之前」把它们脱敏掉。

真实场景中，这里换成任意现成 MCP server(文件系统、数据库、内部 API…)，
AgentGate 代理无需改动即可挡在它前面。
"""

from __future__ import annotations

import json
import sys

try:
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

TOOLS = [
    {"name": "read_customer_record", "description": "读取客户档案",
     "inputSchema": {"type": "object", "properties": {"customer_id": {"type": "string"}}}},
    {"name": "web_search", "description": "联网搜索",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
    {"name": "issue_refund", "description": "发起退款(破坏性/需授权)",
     "inputSchema": {"type": "object", "properties": {"order": {"type": "string"}, "amount": {"type": "number"}}}},
    {"name": "delete_records", "description": "删除记录(破坏性/需授权)",
     "inputSchema": {"type": "object", "properties": {"table": {"type": "string"}, "where": {"type": "string"}}}},
]


def _text_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def handle(msg: dict) -> dict | None:
    method = msg.get("method")
    rpc_id = msg.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock-mcp-server", "version": "0.1.0"},
        }}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "read_customer_record":
            # 故意混入密钥与 PII —— 用于证明代理会脱敏后再回传
            text = (
                f"customer_id={args.get('customer_id')} "
                "name=Jane Doe email=jane.doe@example.com "
                "internal_api_key=sk-live-AbCdEf0123456789ZyXwVu98765432 "
                "note=VIP"
            )
            return {"jsonrpc": "2.0", "id": rpc_id, "result": _text_result(text)}
        if name == "web_search":
            return {"jsonrpc": "2.0", "id": rpc_id,
                    "result": _text_result(f"results for: {args.get('q')}")}
        # 破坏性工具理论上会被代理拦在上游，这里给个兜底返回
        return {"jsonrpc": "2.0", "id": rpc_id,
                "result": _text_result(f"(executed {name} with {args})")}

    if rpc_id is None:
        return None  # 通知类消息，无需回复
    return {"jsonrpc": "2.0", "id": rpc_id,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


def main() -> None:
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
