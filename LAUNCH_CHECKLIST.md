# Launch checklist — AgentGate + MCP-SP v0.2

## Pre-flight (30 min)

- [ ] Replace `agentgate` GitHub org/username in links if not using `agentgate/agentgate`
- [ ] Set `security@yourdomain` in [SECURITY.md](./SECURITY.md)
- [ ] `python -m pytest -q` → all green locally
- [ ] `python demo_mcp.py` → audit PASS + HTML report
- [ ] `mcp-sp agentgate_audit.ndjson --anchors agentgate_anchors.ndjson --require 3`
- [ ] Open `web/danger.html` + `web/compare.html` — demo works
- [ ] `assets/danger_demo.gif` present in repo (README embed)

## GitHub

- [ ] Push `main`
- [ ] Enable **GitHub Pages** (Actions source) → live demo at `/`
- [ ] Add topics: `mcp`, `ai-agents`, `security`, `self-hosted`, `audit`
- [ ] Create release tag `v0.2.0` (triggers [release.yml](./.github/workflows/release.yml) if `PYPI_TOKEN` set)

## PyPI (optional)

```bash
pip install build twine
python -m build && cd mcp-sp && python -m build
# TWINE_PASSWORD=... twine upload dist/*
```

## Show HN / MCP community

- [ ] Post **standard-first** thread (MCP-SP RFC) — see internal `发布包_上线即用.md` if available
- [ ] First comment: link SPEC + `pip install mcp-sp` + danger demo GIF
- [ ] Open GitHub Discussion for spec feedback
- [ ] Add first external row to [mcp-sp/IMPLEMENTERS.md](./mcp-sp/IMPLEMENTERS.md) when someone adopts

## Enterprise pilots

- [ ] Read [docs/PILOT.md](./docs/PILOT.md) — ICP, pricing, outreach templates, SOW acceptance
- [ ] Send `policy-templates/` + `deploy/docker/docker-compose.yml` to 3 design partners
- [ ] Offer paid pilot: audit export + MCP-SP Level 3 conformance report (`scripts/pilot_deliver.py`)
- [ ] Track: stars, spec comments, `mcp-sp` downloads, inbound pilot calls

## Day-7 signals

| Signal | Action |
|---|---|
| Spec critique on identity/L2 | Reply in public; cut v0.2.1 |
| "Can I put this in front of my MCP server?" | Send `examples/cursor.mcp.json` |
| Competitor implements MCP-SP | Add to IMPLEMENTERS + blog post |

---

**One-liner:** You're not selling a library — you're proposing the **MCP security profile** with a reference gate, a one-file validator, and a 30-second demo that shows ungoverned vs Level 3 side by side.
