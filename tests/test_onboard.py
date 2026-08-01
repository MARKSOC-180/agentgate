"""onboard / start：极简入口行为。"""

import json
import os

from agentgate.onboard import ensure_config, write_cursor_snippet


def test_ensure_config_creates_once(tmp_path):
    cfg = tmp_path / "agentgate.config.json"
    path, created = ensure_config(str(cfg), downstream="python server.py")
    assert created is True
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["command"] == "python"
    assert data["args"] == ["server.py"]
    path2, created2 = ensure_config(str(cfg))
    assert created2 is False
    assert path == path2


def test_cursor_snippet(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text("{}", encoding="utf-8")
    out = write_cursor_snippet(str(cfg), str(tmp_path / "snip.json"))
    snip = json.loads(open(out, encoding="utf-8").read())
    assert "protected-tools" in snip["mcpServers"]
    assert snip["mcpServers"]["protected-tools"]["command"] == "agentgate"
