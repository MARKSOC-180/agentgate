"""TypeScript MCP-SP 验证器与 Python 向量一致性(需 Node.js)。"""

import json
import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TS = os.path.join(ROOT, "mcp-sp", "stubs", "ts", "mcp_sp.ts")
VEC = os.path.join(ROOT, "mcp-sp", "conformance_vectors")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_ts_validator_matches_vectors():
    manifest = json.load(open(os.path.join(VEC, "vectors.json"), encoding="utf-8"))
    node_cmd = ["node", "--experimental-strip-types", TS]
    # fallback: plain node if ts not supported
    probe = subprocess.run(["node", "--version"], capture_output=True, text=True)
    if probe.returncode != 0:
        pytest.skip("node unavailable")
    for audit_file, spec in manifest.items():
        audit = os.path.join(VEC, audit_file)
        cmd = node_cmd + [audit]
        if spec.get("anchors"):
            cmd += ["--anchors", os.path.join(VEC, spec["anchors"])]
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        if out.returncode != 0 and "Unknown file extension" in (out.stderr or ""):
            pytest.skip("node cannot run .ts without strip-types")
        assert out.returncode == 0, out.stderr
        level = None
        for line in out.stdout.splitlines():
            if "Level" in line:
                parts = line.replace(":", " ").split()
                for p in parts:
                    if p.isdigit():
                        level = int(p)
        assert level == spec["expected_level"], f"{audit_file}: got {level}"
