# 🛡️ AgentGate

[![MCP-SP](https://img.shields.io/badge/MCP--SP-Level%203-brightgreen)](./SPEC.md)

**自托管的 AI Agent 控制平面。** 夹在 AI agent 与工具（MCP server / 函数）之间，在每一次工具调用上执行：**策略治理 · 密钥/PII 脱敏 · 危险动作拦截 · 限流与预算 · 人在环审批 · 实时告警 · 不可篡改审计 · 结构化追踪**。

![同一 agent、同一批调用 — 无治理 vs MCP-SP Level 3](assets/danger_demo.gif)

*▶ [打开现场演示](web/danger.html) · 单文件、免安装 · 完全在浏览器运行。*

> 你的 agent 接入了越来越多工具（尤其通过 MCP）。一旦它能读数据、发请求、跑命令——就可能泄露密钥、越权操作、执行破坏性动作，而且**静默发生、没有审计**。AgentGate 是那道关。

> **▶ 30 秒体验：** [`web/danger.html`](web/danger.html) · [`web/audit.html`](web/audit.html) · [`web/compare.html`](web/compare.html) · 文档 [`docs/QUICKSTART.md`](docs/QUICKSTART.md) · [`LAUNCH_CHECKLIST.md`](LAUNCH_CHECKLIST.md)

---

## 安装

```bash
pip install -e .          # 零运行时依赖；安装 `agentgate` CLI
```

## 30 秒上手

```bash
python demo.py          # 库模式演示
python demo_mcp.py      # MCP stdio 代理端到端
agentgate report agentgate_audit.ndjson --out agentgate_report.html
```

## CLI

```bash
agentgate proxy  --config agentgate.config.json   # 挡在任意 MCP server 前
agentgate verify [audit.ndjson] --anchors a.ndjson
agentgate anchor [audit.ndjson] --out a.ndjson
agentgate export [audit.ndjson] --out out_dir     # Markdown + CSV + JSON + CEF
agentgate report [audit.ndjson] --out report.html
agentgate metrics [audit.ndjson]                  # Prometheus 指标
agentgate usage [audit.ndjson] --price 0.002      # 按审计链出账单
agentgate intel [intel.ndjson]                    # 威胁情报汇总
agentgate conformance [audit.ndjson] --require 3 --json  # MCP-SP 自证 + CI 门禁
agentgate approvals list --pending
agentgate approvals approve <id>
```

## MCP 代理（零改代码）

```jsonc
// 之前
{ "command": "python", "args": ["my_mcp_server.py"] }
// 之后 — 同一 server，加一道关
{ "command": "agentgate", "args": ["proxy", "--config", "agentgate.config.json"] }
```

详见 [`docs/MCP-PROXY.md`](docs/MCP-PROXY.md) · Cursor 示例 [`examples/cursor.mcp.json`](examples/cursor.mcp.json)

## HTTP 侧车（K8s / Grafana）

配置 `"http": {"host":"127.0.0.1","port":9470}` 后可用：

| 路径 | 用途 |
|---|---|
| `GET /health` | 存活探针 |
| `GET /metrics` | Prometheus |
| `GET /conformance?require=3` | MCP-SP 自证（未达标返回 503） |

---

## 它在每次调用上做什么

| 层 | 作用 |
|---|---|
| **策略** | 允许/拒绝名单、需授权工具、破坏性闸门、tool_scopes、kill-switch |
| **脱敏** | 双向脱敏：OpenAI/Stripe/AWS 密钥、邮箱、卡号、SSN、**中国身份证/手机号/统一社会信用代码** |
| **安全** | 批量删除、命令注入、SSRF、超大额操作 |
| **限流/预算** | `limits` 配置 + 审计 `limits.checked` |
| **人在环** | `require_approval_tools` → 审计 `block` + `approval.pending` → 批准后 `_approval_id` 重试 |
| **审计** | 哈希链、`verify()`、外部锚定 → MCP-SP Level 3 |
| **追踪** | 脱敏后可回放的结构化 span |

```python
ok, msg = gate.audit.verify()   # 篡改会立刻失败并指出记录序号
```

---

## v0.2 新增（MCP 代理 · 标准 · 企业）

| 能力 | 说明 |
|---|---|
| **MCP stdio 代理** | `agentgate proxy --config agentgate.config.json` |
| **MCP-SP 标准** | [SPEC.md](./SPEC.md) · `pip install mcp-sp` · [IMPLEMENTERS.md](./mcp-sp/IMPLEMENTERS.md) |
| **身份/委托 §2.10** | grants 交集衰减 |
| **限流/审批/锚定** | `limits` / `approvals_path` / `anchor_path` + webhook |
| **合规导出** | Markdown + CSV + **JSON + CEF** · [docs/COMPLIANCE.md](./docs/COMPLIANCE.md) |
| **部署** | Docker Compose · K8s sidecar · [policy-templates/](./policy-templates/) |
| **测试** | **118 pytest**（含 TS 验证器、HTTP 侧车、审批 E2E） |

```bash
mcp-sp agentgate_audit.ndjson --anchors agentgate_anchors.ndjson --require 3
node --experimental-strip-types mcp-sp/stubs/ts/mcp_sp.ts agentgate_audit.ndjson
```

运维：[docs/RUNBOOK.md](./docs/RUNBOOK.md) · 威胁模型：[THREAT_MODEL.md](./THREAT_MODEL.md)

---

## 商业

核心开源。付费方向：团队策略仪表盘、RBAC/SSO、合规包托管交付。
**敏感数据始终留在客户墙内** — 与托管 SaaS 的根本区别。

