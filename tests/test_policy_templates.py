"""policy-templates/ 配置必须能被 Limiter/Alerter/Policy 正确加载。"""

import json
import os

import pytest

from agentgate.limits import Limiter
from agentgate.alerts import Alerter
from agentgate.policy import Policy

ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policy-templates")


@pytest.mark.parametrize("name", [
    "filesystem-readonly.config.json",
    "postgres-governed.config.json",
    "shell-deny-all.config.json",
])
def test_policy_template_loads(name):
    path = os.path.join(ROOT, name)
    cfg = json.load(open(path, encoding="utf-8"))
    Policy.from_dict(cfg.get("policy", {}))
    if cfg.get("limits"):
        Limiter.from_dict(cfg["limits"])
    if cfg.get("alerts"):
        Alerter.from_dict(cfg["alerts"])
