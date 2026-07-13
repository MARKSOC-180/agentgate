# Policy templates（策略模板）

开箱即用的 `agentgate.config.json` 片段，复制后改 `command` / `args` 即可。

| 文件 | 场景 |
|---|---|
| `filesystem-readonly.config.json` | 文件系统 MCP：只读 + 脱敏，禁止写/删 |
| `postgres-governed.config.json` | 数据库 MCP：限流 + 破坏性 SQL 需审批 |
| `shell-deny-all.config.json` | 默认拒绝一切 shell / 高危工具 |

## 用法

```bash
cp policy-templates/filesystem-readonly.config.json my.config.json
# 编辑 command/args 指向你的 MCP server
agentgate proxy --config my.config.json
```

配合 Docker：`deploy/docker/docker-compose.yml` 挂载配置与 `/data` 审计卷。

HTTP 侧车（健康检查 / Prometheus / MCP-SP 自证）在配置中加：

```json
"http": { "host": "127.0.0.1", "port": 9470 }
```

K8s 探针示例见 `deploy/k8s/agentgate-sidecar.yaml`。
