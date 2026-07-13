# Changelog

## [0.2.0] — 2026-06-30

### MCP-SP (standard)

- **v0.2 draft**: §2.10 Identity & delegation (attenuated grants)
- JSON Schemas: `schema/audit-record.schema.json`, `schema/anchor-record.schema.json`
- Validator: §2.10 identity + §2.4/§2.5 limits/approval extension checks
- **12 conformance vectors** (identity triple-hop, governed extensions, bad limits, …)
- `pip install mcp-sp` · TypeScript stub `mcp-sp/stubs/ts/mcp_sp.ts`
- `mcp-sp/IMPLEMENTERS.md` adoption registry

### AgentGate (reference implementation)

- Identity, tool_scopes, PrincipalResolver + `resolver_module` config + `_auth_token`
- MCP proxy: anchor/approvals/identity/ENV paths, `anchor_webhook`, MCP-SP `initialize` ad (with `anchoring: true`)
- Compliance: JSON + CEF export; HIPAA assistive mappings
- CN PII: 身份证 / 手机号 / 统一社会信用代码
- Policy templates (filesystem / postgres / shell-deny) — schema-aligned
- Docker hardened (non-root) + compose example config; K8s sidecar manifest
- Web: `danger.html`, `compare.html`, `audit.html` + GIF; GitHub Pages workflow
- Docs: QUICKSTART, MCP-PROXY, RUNBOOK, COMPLIANCE
- Examples: `cursor.mcp.json`, `02_langchain.py`
- HTTP sidecar: `GET /health`, `/metrics`, `/conformance` (`agentgate/http_sidecar.py`)
- CI: CodeQL, JSON Schema validate, policy-template smoke, coverage, TS validator
- **112 pytest**; release + pages workflows

## [0.2.1] — 2026-06-30 (in-tree)

### 标准 / 验证器
- SPEC：§3 `hold-for-approval` → 审计 `block` + `approval.pending` 映射；§3.1 锚点小节
- `bad_approval` conformance 向量（13 条）
- TS/Python canonical 跨语言哈希对齐（浮点 `.0` 字面量）

### 产品 / 部署
- HTTP `/conformance?require=N` 未达标返回 503（K8s readiness）
- Docker/K8s/示例配置启用 HTTP 侧车 `9470`
- `agentgate conformance --json` / `--badge-only`
- `web/audit.html` 浏览器内 MCP-SP 哈希校验（与 Python 一致）
- `web/danger.html` 审批步语义修正

### 测试 / 文档
- 审批全流程 E2E（pending → approve → `_approval_id` 重试）
- CLI 集成测试扩容（anchor / approvals / metrics / conformance JSON）
- CI：锚点 JSON Schema + HTTP 侧车 smoke
- `README_zh.md` 与英文 README 对齐；`policy-templates/README.md`

## [0.1.0] — initial

- Gateway control plane, MCP stdio proxy, metering, threat intel, conformance, compliance export
