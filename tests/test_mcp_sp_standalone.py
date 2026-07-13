"""
独立标准验证器 mcp-sp/mcp_sp.py 的测试。

意义：MCP-SP 必须能脱离 AgentGate 独立存在——任何人 copy 单文件即可自证合规。
这里用 subprocess 调用真实 CLI 跑全部一致性向量，断言每个向量产出 manifest 里
记录的预期等级；并交叉验证「独立验证器」与「agentgate 内置 conformance」结论一致。
"""

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MCP_SP_DIR = os.path.join(ROOT, "mcp-sp")
MCP_SP = os.path.join(MCP_SP_DIR, "mcp_sp.py")
VEC = os.path.join(MCP_SP_DIR, "conformance_vectors")


def _run(audit, anchors=None):
    cmd = [sys.executable, MCP_SP, audit, "--json"]
    if anchors:
        cmd += ["--anchors", anchors]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return json.loads(out.stdout)


def _manifest():
    with open(os.path.join(VEC, "vectors.json"), encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.skipif(not os.path.exists(os.path.join(VEC, "vectors.json")),
                    reason="vectors not generated; run mcp-sp/make_vectors.py")
def test_standalone_validator_matches_manifest():
    manifest = _manifest()
    assert manifest, "no conformance vectors found"
    for audit_file, spec in manifest.items():
        audit = os.path.join(VEC, audit_file)
        anchors = os.path.join(VEC, spec["anchors"]) if spec.get("anchors") else None
        res = _run(audit, anchors)
        assert res["level"] == spec["expected_level"], (
            f"{audit_file}: expected level {spec['expected_level']}, got {res['level']}")


def test_standalone_has_zero_third_party_imports():
    """单文件必须零第三方依赖：只允许标准库 import。"""
    src = open(MCP_SP, encoding="utf-8").read()
    assert "import agentgate" not in src
    assert "from agentgate" not in src


def test_require_gate_exit_code():
    audit = os.path.join(VEC, "valid_level2.ndjson")
    # 要求 Level 3 但只有 Level 2 -> 退出码非 0(CI 门禁应失败)
    r = subprocess.run([sys.executable, MCP_SP, audit, "--require", "3"],
                       capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 1
    # 要求 Level 2 且确实是 Level 2 -> 退出码 0
    r2 = subprocess.run([sys.executable, MCP_SP, audit, "--require", "2"],
                        capture_output=True, text=True, encoding="utf-8")
    assert r2.returncode == 0


def test_agrees_with_agentgate_conformance():
    """独立验证器与 agentgate 内置 conformance 对同一日志结论一致。"""
    from agentgate.conformance import check_conformance
    audit = os.path.join(VEC, "valid_level2.ndjson")
    standalone = _run(audit)
    builtin = check_conformance(audit)
    assert standalone["level"] == builtin["level"] == 2
