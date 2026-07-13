# AgentGate 运维 Runbook

## 日常

| 任务 | 命令 |
|---|---|
| 校验审计链 | `agentgate verify /data/audit.ndjson --anchors /data/anchors.ndjson` |
| MCP-SP 自证 | `mcp-sp /data/audit.ndjson --anchors /data/anchors.ndjson --require 3` |
| 合规包 | `agentgate export /data/audit.ndjson --out compliance_export` |
| 实时指标 | `agentgate metrics` (Prometheus scrape) |

## 审批 SLA

1. 用户/agent 触发 `require_approval_tools` → 审计记录带 `approval.status=pending`
2. 运维: `agentgate approvals list` → `agentgate approvals approve <id>`
3. 重试工具调用时传 `_approval_id` 参数

## 备份

- **审计链** `/data/audit.ndjson` — append-only，每日复制到 WORM/对象存储
- **锚点** `/data/anchors.ndjson` — 与审计链一起备份；可选 `anchor_webhook` 推送到 SIEM
- **审批库** `/data/approvals.json` — 与审计链一致性相关

## 事件响应

| 信号 | 动作 |
|---|---|
| verify FAIL | 隔离代理进程；保留磁盘镜像；查 anchor 是否被重写 |
| 大量 block + critical safety | 启用 `policy.killswitch` 或 Deny-all 模板 |
| intel feed 异常聚类 | 更新 deny_tools / safety 规则；导出 `agentgate intel export` |

## 升级

```bash
pip install -U agentgate mcp-sp
python mcp-sp/make_vectors.py && mcp-sp audit.ndjson --require 3
```

见 [THREAT_MODEL.md](../THREAT_MODEL.md) · [docs/COMPLIANCE.md](./COMPLIANCE.md)
