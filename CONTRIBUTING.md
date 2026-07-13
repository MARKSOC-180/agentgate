# Contributing to AgentGate & MCP-SP

Thank you for helping make agent tool-call governance a **standard**, not a vendor feature.

## What we need most

1. **Critique of [SPEC.md](./SPEC.md)** — especially §2.10 identity/delegation and L2 evidence model.
2. **Conformance vectors** — edge cases that break naive validators.
3. **Implementations in other languages** — must agree with `mcp-sp/conformance_vectors/vectors.json`.
4. **Policy templates** — real MCP server configs under `policy-templates/`.
5. **Bug reports** with reproducible audit logs (redact secrets first).

## Dev setup

```bash
git clone https://github.com/agentgate/agentgate.git
cd agentgate
pip install -e ".[dev]"
python -m pytest -q
python mcp-sp/make_vectors.py
python mcp-sp/mcp_sp.py mcp-sp/conformance_vectors/valid_level2.ndjson --require 2
```

## Pull request checklist

- [ ] Tests pass (`python -m pytest -q`)
- [ ] If you changed audit record shape → update SPEC §3 + JSON Schema + regenerate vectors
- [ ] If you changed MCP-SP validator → all vectors still pass
- [ ] No secrets in commits
- [ ] One logical change per PR when possible

## Spec changes

MCP-SP is intentionally a draft. Propose spec changes in PRs against `SPEC.md` with:

- Motivation (what production gap?)
- Normative text (RFC 2119 keywords)
- Conformance impact (which level?)
- At least one new vector if behavior is testable

## Code style

- Python 3.8+, stdlib-only for runtime code
- Minimal scope — match surrounding style
- Comments for non-obvious business logic only

## Security

See [SECURITY.md](./SECURITY.md). Do **not** open public issues for vulnerabilities.

## License

By contributing, you agree your contributions are licensed under Apache-2.0.
