"""
http_sidecar.py —— 零依赖 HTTP 侧车(健康检查 / Prometheus / MCP-SP 自证)。

企业要把控制平面接进 K8s / 负载均衡 / Grafana，但核心代理仍是 stdio MCP。
本模块在后台线程起一个极简 HTTP 服务，只读本地审计/锚点文件，不碰 MCP 协议通道。

端点：
  GET /health          → {"ok": true, "service": "agentgate"}
  GET /metrics         → Prometheus 文本(来自审计链)
  GET /conformance     → MCP-SP JSON(需 query: audit=, anchors=)
  GET /                → 简单状态页

纯标准库。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse


class _Handler(BaseHTTPRequestHandler):
    audit_path: str = "agentgate_audit.ndjson"
    anchors_path: Optional[str] = None
    mcp_sp_level: int = 3

    def log_message(self, fmt, *args):
        pass  # 安静；MCP stdio 通道的 stderr 留给代理日志

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._send(200, b'{"ok":true,"service":"agentgate"}\n', "application/json")
            return
        if path == "/metrics":
            from .metrics import prometheus_text
            text = prometheus_text(self.audit_path)
            self._send(200, text.encode("utf-8"), "text/plain; version=0.0.4")
            return
        if path == "/conformance":
            qs = parse_qs(urlparse(self.path).query)
            audit = (qs.get("audit") or [self.audit_path])[0]
            anchors = (qs.get("anchors") or [self.anchors_path or ""])[0] or None
            require_raw = (qs.get("require") or [""])[0]
            from .conformance import check_conformance
            res = check_conformance(audit, anchors_path=anchors,
                                    capabilities={"selfHosted": True})
            body = json.dumps(res, ensure_ascii=False, indent=2).encode("utf-8")
            if str(require_raw).isdigit():
                code = 200 if res.get("level", 0) >= int(require_raw) else 503
            else:
                code = 200
            self._send(code, body, "application/json")
            return
        if path in ("/", "/status"):
            html = (f"<html><body><h1>AgentGate sidecar</h1>"
                    f"<p>MCP-SP target level: {self.mcp_sp_level}</p>"
                    f"<ul><li><a href='/health'>/health</a></li>"
                    f"<li><a href='/metrics'>/metrics</a></li>"
                    f"<li><a href='/conformance'>/conformance</a></li></ul></body></html>")
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(404, b"not found\n", "text/plain")


def start_http_sidecar(host: str, port: int, audit_path: str,
                       anchors_path: Optional[str] = None,
                       mcp_sp_level: int = 3) -> HTTPServer:
    """在守护线程启动 HTTP 侧车，返回 server 实例(调用方负责进程退出时 shutdown)。"""
    handler = type("AgentGateHTTP", (_Handler,), {
        "audit_path": audit_path,
        "anchors_path": anchors_path,
        "mcp_sp_level": mcp_sp_level,
    })
    server = HTTPServer((host, port), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
