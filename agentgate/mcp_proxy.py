"""
mcp_proxy.py —— MCP stdio 代理(把 AgentGate 挡在任意 MCP server 前面)。

这是「从库升级到网关基础设施」的关键一跃：
客户端(Cursor / Claude Desktop / 任意 MCP host)不改一行代码——只把原来指向
真实 MCP server 的命令，改成指向本代理；代理在内部拉起真实 server 作为子进程，
并对每一次 `tools/call` 套上完整控制平面：

    上游 client ──stdio──▶ [AgentGate 代理] ──stdio──▶ 真实 MCP server(子进程)
                              │
                              ├─ 执行前：策略判定 + 安全扫描 + 输入脱敏
                              ├─ 拦截：直接合成「被拦截」结果，绝不转发给下游
                              └─ 放行：转发；下游返回后对输出脱敏 + 审计上链，再回传

设计要点：
- MCP stdio 传输是「按行分隔的 JSON-RPC」。stdout 只走协议消息，
  所有人类可读日志一律写 stderr，绝不污染协议通道。
- 只拦 `tools/call`，其余方法(initialize / tools/list / ...)透明转发，零侵入。
- 对 `initialize` 响应注入 MCP-SP 能力广告(SPEC §5)。
- 零外部依赖：subprocess + threading + json 全标准库。

用法：
    python -m agentgate.mcp_proxy --config agentgate.config.json
    python -m agentgate.mcp_proxy --downstream "python my_mcp_server.py"
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import threading
import time
from typing import Optional, Union

from .gateway import Gateway
from .policy import Policy
from .limits import Limiter
from .alerts import Alerter
from .metering import Meter, Pricing
from .intel import ThreatIntel
from .anchoring import Anchor
from .approvals import ApprovalStore
from .identity import Identity, coerce_identity, principal_id, resolve_token


def _log(msg: str) -> None:
    """人类可读日志一律走 stderr，避免污染 stdout 的 JSON-RPC 协议通道。"""
    sys.stderr.write(f"[AgentGate] {msg}\n")
    sys.stderr.flush()


class MCPProxy:
    def __init__(self, downstream_argv: list, gateway: Gateway,
                 principal: Union[str, Identity] = "mcp-client",
                 pre_authorized_tools: Optional[set] = None,
                 mcp_sp_level: int = 3):
        self.downstream_argv = downstream_argv
        self.gate = gateway
        self.principal = principal
        self.pre_authorized = set(pre_authorized_tools or set())
        self.mcp_sp_level = mcp_sp_level

        self.proc: Optional[subprocess.Popen] = None
        self._pending: dict = {}
        self._pending_lock = threading.Lock()
        self._out_lock = threading.Lock()
        self._down_lock = threading.Lock()
        self._init_id = None

    def _effective_principal(self):
        return self.principal

    def _send_upstream(self, msg: dict) -> None:
        with self._out_lock:
            sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
            sys.stdout.flush()

    def _send_downstream(self, raw_line: str) -> None:
        with self._down_lock:
            self.proc.stdin.write(raw_line if raw_line.endswith("\n") else raw_line + "\n")
            self.proc.stdin.flush()

    def _enrich_initialize(self, msg: dict) -> dict:
        """SPEC §5：在 initialize 响应里广告 MCP-SP 能力。"""
        if self._init_id is None or msg.get("id") != self._init_id:
            return msg
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        caps = dict(result.get("capabilities") or {})
        exp = dict(caps.get("experimental") or {})
        exp["mcp-sp"] = {
            "version": "0.2",
            "level": self.mcp_sp_level,
            "selfHosted": True,
            "anchoring": getattr(self.gate, "anchor", None) is not None,
            "validator": "mcp-sp/mcp_sp.py",
        }
        caps["experimental"] = exp
        result["capabilities"] = caps
        msg["result"] = result
        self._init_id = None
        return msg

    def _handle_tool_call(self, msg: dict, raw_line: str) -> None:
        rpc_id = msg.get("id")
        params = msg.get("params") or {}
        tool = params.get("name", "<unknown>")
        args = params.get("arguments", {}) or {}

        principal = self._effective_principal()
        # 可选：从工具参数 _auth_token 解析 Identity(OIDC/SPIFFE 插件)
        if isinstance(args, dict) and args.get("_auth_token"):
            resolved = resolve_token(str(args.pop("_auth_token")))
            if resolved is not None:
                principal = resolved

        pid = principal_id(principal)
        identity = coerce_identity(principal)
        authorized = tool in self.pre_authorized
        approval_id = args.get("_approval_id") if isinstance(args, dict) else None
        t0 = time.time()
        decision, safety, red_inputs, hits, limits_record = self.gate.precheck(
            tool, args, principal=pid, authorized=authorized,
            approval_id=approval_id, identity=identity)

        if not decision.allowed:
            self.gate.finalize(tool, red_inputs, decision, safety, hits,
                               output=None, principal=principal, t0=t0,
                               limits_record=limits_record)
            reason = "；".join(decision.reasons) or "policy"
            _log(f"tools/call {tool} -> BLOCK ({reason})")
            self._send_upstream({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": f"⛔ AgentGate blocked tool `{tool}`: {reason}",
                    }],
                    "isError": True,
                },
            })
            return

        with self._pending_lock:
            self._pending[rpc_id] = {
                "tool": tool, "red_inputs": red_inputs, "decision": decision,
                "safety": safety, "hits": hits, "t0": t0, "principal": principal,
                "limits_record": limits_record,
            }
        _log(f"tools/call {tool} -> ALLOW (forwarding)")
        self._send_downstream(raw_line)

    def _handle_downstream_response(self, msg: dict, raw_line: str) -> None:
        msg = self._enrich_initialize(msg)
        rpc_id = msg.get("id")
        ctx = None
        if rpc_id is not None:
            with self._pending_lock:
                ctx = self._pending.pop(rpc_id, None)

        if ctx is None:
            self._send_upstream(msg)
            return

        result = msg.get("result")
        cr = self.gate.finalize(
            ctx["tool"], ctx["red_inputs"], ctx["decision"], ctx["safety"],
            ctx["hits"], output=result, principal=ctx["principal"], t0=ctx["t0"],
            limits_record=ctx.get("limits_record"))
        if cr.redaction_hits:
            total = sum(cr.redaction_hits.values())
            _log(f"redacted {total} secret/PII hit(s) in `{ctx['tool']}` response")
        msg["result"] = cr.output
        self._send_upstream(msg)

    def _pump_upstream_to_downstream(self) -> None:
        for raw_line in sys.stdin:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except Exception:
                self._send_downstream(raw_line)
                continue
            if isinstance(msg, dict) and msg.get("method") == "initialize":
                self._init_id = msg.get("id")
            if isinstance(msg, dict) and msg.get("method") == "tools/call":
                self._handle_tool_call(msg, line)
            else:
                self._send_downstream(line)
        try:
            self.proc.stdin.close()
        except Exception:
            pass

    def _pump_downstream_to_upstream(self) -> None:
        for raw_line in self.proc.stdout:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except Exception:
                with self._out_lock:
                    sys.stdout.write(raw_line)
                    sys.stdout.flush()
                continue
            if isinstance(msg, dict) and "id" in msg and ("result" in msg or "error" in msg):
                self._handle_downstream_response(msg, line)
            else:
                self._send_upstream(msg)

    def run(self) -> int:
        _log(f"starting downstream: {' '.join(self.downstream_argv)}")
        http_srv = getattr(self, "_http_server", None)
        if http_srv:
            _log(f"HTTP sidecar listening on {http_srv.server_address[0]}:{http_srv.server_address[1]}")
        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        self.proc = subprocess.Popen(
            self.downstream_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=None, text=True, encoding="utf-8", bufsize=1, env=env,
        )
        up = threading.Thread(target=self._pump_upstream_to_downstream, daemon=True)
        up.start()
        self._pump_downstream_to_upstream()
        code = self.proc.wait()
        meter = getattr(self.gate, "meter", None)
        if meter is not None:
            snap = meter.snapshot()
            t = snap["totals"]
            cur = snap["pricing"]["currency"]
            _log(f"usage this session: {t['calls']} calls, "
                 f"{t['billable']} billable -> {t['amount']:.4f} {cur}")
        _log(f"downstream exited with code {code}")
        return code


def _webhook_sink(url: str):
    """构造 anchor webhook sink(POST JSON 到外部不可变存储/日志)。"""
    import urllib.request
    def _post(rec: dict) -> None:
        data = json.dumps(rec, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        urllib.request.urlopen(req, timeout=10)  # noqa: S310
    return _post


def build_proxy_from_config(cfg: dict) -> MCPProxy:
    """从配置 dict 构造代理。"""
    if cfg.get("resolver_module"):
        from .identity import load_resolver_module
        load_resolver_module(cfg["resolver_module"])

    command = cfg.get("command")
    if command is None:
        raise ValueError("配置缺少 `command`(下游 MCP server 的启动命令)")
    argv = command if isinstance(command, list) else shlex.split(command)
    argv = argv + list(cfg.get("args", []) or [])

    meter = None
    if cfg.get("pricing") or cfg.get("usage_path"):
        meter = Meter(pricing=Pricing.from_dict(cfg.get("pricing", {})),
                      usage_path=cfg.get("usage_path"))
    intel = None
    if cfg.get("intel") or cfg.get("intel_path"):
        intel = ThreatIntel(cfg.get("intel_path", "agentgate_intel.ndjson"))

    anchor = None
    anchor_path = cfg.get("anchor_path") or os.environ.get("AGENTGATE_ANCHORS")
    if anchor_path:
        sink = None
        if cfg.get("anchor_webhook"):
            sink = _webhook_sink(cfg["anchor_webhook"])
        anchor = Anchor(anchor_path, sink=sink)

    policy = Policy.from_dict(cfg.get("policy", {}))
    approvals = None
    if cfg.get("approvals_path") or policy.require_approval_tools:
        approvals = ApprovalStore(cfg.get("approvals_path", "agentgate_approvals.json"))

    principal: Union[str, Identity] = cfg.get("principal", "mcp-client")
    if cfg.get("identity"):
        principal = Identity.from_dict(cfg["identity"])

    audit_path = cfg.get("audit_path") or os.environ.get("AGENTGATE_AUDIT", "agentgate_audit.ndjson")
    trace_path = cfg.get("trace_path") or os.environ.get("AGENTGATE_TRACE", "agentgate_trace.ndjson")

    gateway = Gateway(
        policy=policy,
        audit_path=audit_path,
        trace_path=trace_path,
        limits=Limiter.from_dict(cfg["limits"]) if cfg.get("limits") else None,
        alerts=Alerter.from_dict(cfg["alerts"]) if cfg.get("alerts") else None,
        approvals=approvals,
        anchor=anchor,
        anchor_every=int(cfg.get("anchor_every", 0) or 0),
        meter=meter, intel=intel,
    )
    proxy = MCPProxy(
        downstream_argv=argv, gateway=gateway,
        principal=principal,
        pre_authorized_tools=set(cfg.get("pre_authorized_tools", []) or []),
        mcp_sp_level=int(cfg.get("mcp_sp_level", 3)),
    )
    proxy._http_server = _maybe_start_http(cfg, audit_path, anchor_path, proxy.mcp_sp_level)
    return proxy


def _maybe_start_http(cfg: dict, audit_path: str, anchor_path: Optional[str],
                      mcp_sp_level: int) -> Optional[object]:
    from .http_sidecar import start_http_sidecar
    http = cfg.get("http") or {}
    port = http.get("port") or cfg.get("http_port")
    if not port:
        return None
    host = http.get("host", "127.0.0.1")
    return start_http_sidecar(host, int(port), audit_path, anchor_path, mcp_sp_level)


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(
        description="AgentGate MCP 代理：把控制平面挡在任意 MCP server 前面。")
    p.add_argument("--config", help="JSON 配置文件路径(含 command/policy/...)")
    p.add_argument("--downstream", help="下游 MCP server 启动命令(与 --config 二选一)")
    args = p.parse_args(argv)

    try:
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if args.config:
        with open(args.config, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    elif args.downstream:
        cfg = {"command": args.downstream}
    else:
        p.error("必须提供 --config 或 --downstream 之一")
        return 2

    proxy = build_proxy_from_config(cfg)
    try:
        return proxy.run()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
