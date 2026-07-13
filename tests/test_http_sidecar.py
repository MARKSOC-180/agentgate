"""HTTP 侧车：/health /metrics /conformance。"""

import json
import threading
import urllib.error
import urllib.request

from agentgate.gateway import Gateway
from agentgate.policy import Policy
from agentgate.http_sidecar import start_http_sidecar


def test_http_sidecar_endpoints(tmp_path):
    audit = str(tmp_path / "a.ndjson")
    gw = Gateway(policy=Policy(), audit_path=audit, trace_path=str(tmp_path / "t.ndjson"))
    gw.call("read", {"x": 1}, handler=lambda i: "ok", principal="u")

    srv = start_http_sidecar("127.0.0.1", 0, audit, mcp_sp_level=2)
    port = srv.server_address[1]

    health = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/health").read())
    assert health["ok"] is True

    metrics = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics").read().decode()
    assert "agentgate_calls_total" in metrics

    conf = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/conformance").read())
    assert conf["level"] >= 1

    # 未达目标等级时应 503（供 K8s readiness 使用）
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/conformance?require=3")
        assert False, "expected HTTP 503"
    except urllib.error.HTTPError as e:
        assert e.code == 503

    srv.shutdown()


def test_http_sidecar_conformance_ok_when_level_met(tmp_path):
    audit = str(tmp_path / "a.ndjson")
    gw = Gateway(policy=Policy(), audit_path=audit, trace_path=str(tmp_path / "t.ndjson"))
    gw.call("read", {"x": 1}, handler=lambda i: "ok", principal="u")

    srv = start_http_sidecar("127.0.0.1", 0, audit, mcp_sp_level=1)
    port = srv.server_address[1]
    resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/conformance?require=1")
    assert resp.status == 200
    srv.shutdown()
