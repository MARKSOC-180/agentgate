"""
onboard.py —— 极致简单的「能用」入口（乔布斯式：一个动作，其余藏起来）。

用户只需要：
    agentgate start
    # 或指定下游：agentgate start --downstream "python my_mcp_server.py"

产出：
    - agentgate.config.json（若尚无）
    - cursor.mcp.snippet.json（复制进 Cursor MCP 配置）
    - 三行以内的下一步（不甩文档墙）
"""

from __future__ import annotations

import json
import os
from typing import Optional, Tuple

DEFAULT_CONFIG = {
    "command": "python",
    "args": ["-c", "print('Replace with your MCP server command')"],
    "audit_path": "agentgate_audit.ndjson",
    "trace_path": "agentgate_trace.ndjson",
    "anchor_path": "agentgate_anchors.ndjson",
    "anchor_every": 50,
    "mcp_sp_level": 3,
    "policy": {
        "deny_tools": ["shell_exec"],
        "destructive_tools": ["delete_records"],
        "require_approval_tools": ["delete_records"],
    },
}


def _split_downstream(cmd: str) -> Tuple[str, list]:
    parts = cmd.strip().split()
    if not parts:
        return "python", ["-c", "print('set --downstream')"]
    return parts[0], parts[1:]


def ensure_config(path: str, downstream: Optional[str] = None) -> Tuple[str, bool]:
    """返回 (config_path, created)。已存在则不覆盖。"""
    path = os.path.abspath(path)
    if os.path.isfile(path):
        return path, False
    cfg = dict(DEFAULT_CONFIG)
    if downstream:
        exe, args = _split_downstream(downstream)
        cfg["command"] = exe
        cfg["args"] = args
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return path, True


def write_cursor_snippet(config_path: str, out_path: str = "cursor.mcp.snippet.json") -> str:
    """给 Cursor / MCP host 用的一段可粘贴配置。"""
    out_path = os.path.abspath(out_path)
    snippet = {
        "mcpServers": {
            "protected-tools": {
                "command": "agentgate",
                "args": ["proxy", "--config", config_path.replace("\\", "/")],
            }
        }
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(snippet, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return out_path


def print_start_card(config_path: str, snippet_path: str, created: bool) -> None:
    """控制台也保持克制：品牌感 + 下一步，不堆术语。"""
    print()
    print("  AgentGate")
    print("  ─────────")
    print("  Every tool call. On your machine. Provable.")
    print()
    if created:
        print(f"  Ready:  {config_path}")
    else:
        print(f"  Using:  {config_path}")
    print(f"  Cursor: {snippet_path}  (paste into MCP config)")
    print()
    print("  Next — one command:")
    print(f'    agentgate proxy --config "{config_path}"')
    print()
    print("  Or open the feeling:")
    print("    https://marksoc-180.github.io/agentgate/start.html")
    print()
