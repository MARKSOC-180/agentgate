"""
test_tamper.py —— 证明哈希链审计真的能抓到篡改。

先跑 demo 生成审计日志，然后偷偷改掉其中一条记录，再 verify()，
看它能不能发现。这验证了 AgentGate 的"不可抵赖"卖点不是吹的。
"""

import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from agentgate import AuditLog

HERE = os.path.dirname(os.path.abspath(__file__))
AUDIT = os.path.join(HERE, "data", "audit.ndjson")

audit = AuditLog(AUDIT)

ok, msg = audit.verify()
print(f"篡改前： {'✓' if ok else '✗'} {msg}")

# 偷偷篡改：把第 3 行里的 'block' 改成 'allow'（模拟有人事后洗白一次越权放行）
with open(AUDIT, "r", encoding="utf-8") as f:
    lines = f.readlines()

if len(lines) >= 3:
    lines[2] = lines[2].replace('"decision": "block"', '"decision": "allow"', 1)
    with open(AUDIT, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print("→ 已偷偷把第 3 条的 block 改成 allow ...")

ok, msg = audit.verify()
print(f"篡改后： {'✓' if ok else '✗'} {msg}")
print("\n结论：", "审计链成功抓到篡改 ✅" if not ok else "未抓到（有问题）❌")
