"""demo_mcp.py 冒烟测试(端到端代理演示)。"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_demo_mcp_runs():
    r = subprocess.run(
        [sys.executable, "demo_mcp.py"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert r.returncode == 0, r.stderr[-500:]
    assert "PASS" in r.stdout or "审计链校验" in r.stdout
    assert os.path.exists(os.path.join(ROOT, "agentgate_audit.ndjson"))
