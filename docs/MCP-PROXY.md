# MCP proxy configuration

## Minimal

```json
{
  "command": "python",
  "args": ["-m", "your_mcp_server"],
  "audit_path": "agentgate_audit.ndjson"
}
```

## Full enterprise sidecar

```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
  "audit_path": "/data/audit.ndjson",
  "trace_path": "/data/trace.ndjson",
  "anchor_path": "/data/anchors.ndjson",
  "anchor_every": 50,
  "approvals_path": "/data/approvals.json",
  "mcp_sp_level": 3,
  "policy": {
    "deny_tools": ["shell_exec"],
    "destructive_tools": ["delete_file"],
    "require_approval_tools": ["delete_file"],
    "tool_scopes": { "delete_file": ["fs:delete"] }
  },
  "identity": {
    "principal": { "id": "agent", "type": "agent", "grants": ["fs:read", "fs:delete"] },
    "on_behalf_of": [{ "id": "user-42", "type": "user", "grants": ["fs:read"] }]
  },
  "limits": { "max_calls_total": 1000 },
  "intel": true,
  "pricing": { "price_per_call": 0.001, "included_calls": 0, "currency": "USD" }
}
```

## Resolver from config (no custom Python required)

```json
{
  "resolver_module": "mycompany.auth.agentgate_resolver",
  "command": "python",
  "args": ["-m", "my_mcp_server"]
}
```

The module must call `register_resolver()` at import time.

## OIDC / SPIFFE (programmatic)

Register a resolver in Python before starting the proxy:

```python
from agentgate.identity import PrincipalResolver, Identity, Principal, register_resolver

class OidcResolver(PrincipalResolver):
    def resolve(self, token: str):
        claims = verify_your_jwt(token)
        return Identity(Principal(claims["sub"], "user", frozenset(claims.get("scope", []))))

register_resolver(OidcResolver())
```

Clients may pass `_auth_token` in tool arguments (stripped before downstream).

## HTTP sidecar (health / metrics / conformance)

```json
{
  "http": { "host": "127.0.0.1", "port": 9470 }
}
```

Endpoints while the MCP proxy runs:

| Path | Purpose |
|---|---|
| `GET /health` | Liveness |
| `GET /metrics` | Prometheus text from audit log |
| `GET /conformance` | MCP-SP JSON result |

## Docker

```bash
docker compose -f deploy/docker/docker-compose.yml up
```

See [deploy/k8s/agentgate-sidecar.yaml](../deploy/k8s/agentgate-sidecar.yaml) for Kubernetes.
