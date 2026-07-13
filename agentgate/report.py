"""
report.py —— 生成「控制平面拦下了什么」的自包含 HTML 报告(世界级英文 UI)。

这是 5 分钟「啊哈」：工程师/CTO 跑一次，立刻看到——我的 agent 刚才差点泄露
几个密钥、被拦下几次越权/破坏性调用、几次被限流挡住，而且这一切都有不可篡改、
可外部锚定的审计链背书。完全本地生成、零外部依赖、数据零外泄。

设计目标：对标 Linear / Vercel / Stripe 的 dashboard 质感——深色 command-center、
精致排版、KPI 卡、完整性徽章、严重度配色。全部内联，单文件可分享。
"""

from __future__ import annotations

import html
import time
from collections import Counter
from datetime import datetime, timezone

from .audit import AuditLog

_SECRET_LABELS = {"OpenAI key", "Stripe secret", "AWS key", "Google key",
                  "GitHub token", "Slack token", "JWT/Supabase", "Private key"}


def _esc(x) -> str:
    return html.escape(str(x))


def _iso(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%b %d, %Y %H:%M UTC")
    except Exception:
        return "—"


def _classify_block(reasons: list) -> str:
    """把拦截原因归类，用于分组统计。"""
    text = " ".join(reasons or []).lower()
    if "human approval" in text:
        return "Held for approval"
    if "rate-limited" in text or "budget" in text:
        return "Rate-limit / budget"
    if "not authorized" in text or "authorization" in text:
        return "Authorization"
    if "destructive" in text:
        return "Destructive gate"
    if "critical safety" in text or "safety risk" in text:
        return "Critical safety"
    if "deny list" in text or "allow list" in text:
        return "Policy list"
    if "kill-switch" in text:
        return "Kill-switch"
    return "Other"


def build_report(audit_path: str, out_path: str = "agentgate_report.html",
                 anchor_path: str = None) -> str:
    audit = AuditLog(audit_path)
    records = audit.load()
    chain_ok, chain_msg = audit.verify()

    total = len(records)
    blocked = [r for r in records if r.get("decision") == "block"]
    allowed = [r for r in records if r.get("decision") == "allow"]

    secrets_redacted = pii_redacted = 0
    sev_counter: Counter = Counter()
    block_reason_counter: Counter = Counter()
    tool_counter: Counter = Counter()
    for r in records:
        for label, n in (r.get("redaction_hits") or {}).items():
            if label in _SECRET_LABELS:
                secrets_redacted += n
            else:
                pii_redacted += n
        for s in (r.get("safety") or []):
            sev_counter[s.split(":", 1)[0]] += 1
        tool_counter[r.get("tool", "—")] += 1
        if r.get("decision") == "block":
            block_reason_counter[_classify_block(r.get("reasons"))] += 1

    safety_flags = sum(sev_counter.values())
    held = block_reason_counter.get("Held for approval", 0)
    first_ts = records[0]["ts"] if records else None
    last_ts = records[-1]["ts"] if records else None

    # 外部锚定状态(可选)
    anchor_block = ""
    if anchor_path:
        import os
        if os.path.exists(anchor_path):
            from .anchoring import Anchor
            anc = Anchor(anchor_path)
            a_ok, a_msg = anc.verify(audit)
            n_anchors = len(anc.records())
            a_color = "#34d399" if a_ok else "#fb7185"
            a_icon = "anchored &amp; verified" if a_ok else "anchor mismatch"
            anchor_block = f"""
        <div class="badge" style="--c:{a_color}">
          <span class="dot"></span>{a_icon}
          <span class="badge-sub">{n_anchors} external anchor(s) · {_esc(a_msg)}</span>
        </div>"""

    # 活动明细表
    rows = ""
    for r in records:
        d = r.get("decision")
        is_block = d == "block"
        pill_cls = "block" if is_block else "allow"
        hits = r.get("redaction_hits") or {}
        hits_html = "".join(
            f'<span class="chip chip-red">{_esc(k)}<b>{v}</b></span>' for k, v in hits.items()
        ) or '<span class="dim">—</span>'
        safety_html = ""
        for s in (r.get("safety") or []):
            sv = s.split(":", 1)[0]
            ttl = s.split(":", 1)[1] if ":" in s else s
            safety_html += f'<span class="chip sev-{sv}">{_esc(ttl)}</span>'
        safety_html = safety_html or '<span class="dim">—</span>'
        reason = "; ".join(r.get("reasons") or []) or "—"
        rows += f"""
        <tr>
          <td><span class="pill {pill_cls}">{_esc(d)}</span></td>
          <td class="mono">{_esc(r.get('tool'))}</td>
          <td class="mono dim">{_esc(r.get('principal') or 'anon')}</td>
          <td class="reason">{_esc(reason)}</td>
          <td>{hits_html}</td>
          <td>{safety_html}</td>
        </tr>"""

    chain_color = "#34d399" if chain_ok else "#fb7185"
    chain_icon = "audit chain intact" if chain_ok else "audit chain broken"

    def _bars(counter: Counter, palette) -> str:
        if not counter:
            return '<div class="dim" style="padding:6px 0">No data</div>'
        mx = max(counter.values())
        out = ""
        for i, (k, v) in enumerate(counter.most_common()):
            c = palette[i % len(palette)]
            pct = int(v / mx * 100)
            out += f"""
            <div class="bar-row">
              <div class="bar-label">{_esc(k)}</div>
              <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{c}"></div></div>
              <div class="bar-val">{v}</div>
            </div>"""
        return out

    blocks_bars = _bars(block_reason_counter, ["#fb7185", "#f59e0b", "#8b5cf6", "#38bdf8"])
    tools_bars = _bars(tool_counter, ["#8b5cf6", "#38bdf8", "#34d399", "#f59e0b"])
    sev_bars = _bars(Counter({k: sev_counter[k] for k in ("critical", "high", "warning") if k in sev_counter}),
                     ["#fb7185", "#f59e0b", "#fbbf24"])

    span = (f"{_iso(first_ts)} &rarr; {_iso(last_ts)}" if records else "—")
    generated = _iso(time.time())

    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentGate — Control Plane Report</title>
<style>
  :root{{
    --bg:#08090d; --panel:#101218; --panel2:#151823; --bd:rgba(255,255,255,.08);
    --bd2:rgba(255,255,255,.13); --tx:#e9ebf2; --muted:#888fa3; --dim:#5c6275;
    --green:#34d399; --red:#fb7185; --amber:#f59e0b; --yellow:#fbbf24;
    --violet:#8b5cf6; --blue:#38bdf8;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  html{{-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}}
  body{{
    font-family:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    color:var(--tx);line-height:1.55;
    background:
      radial-gradient(900px 480px at 12% -8%, rgba(139,92,246,.18), transparent 60%),
      radial-gradient(820px 420px at 92% -4%, rgba(56,189,248,.12), transparent 58%),
      var(--bg);
    min-height:100vh;padding:0 0 60px;
  }}
  .nav{{display:flex;align-items:center;justify-content:space-between;gap:16px;
    padding:18px 34px;border-bottom:1px solid var(--bd);
    background:rgba(8,9,13,.7);backdrop-filter:blur(10px);position:sticky;top:0;z-index:10}}
  .brand{{display:flex;align-items:center;gap:11px;font-weight:700;font-size:17px;letter-spacing:.2px}}
  .brand .logo{{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;
    background:linear-gradient(135deg,var(--violet),var(--blue));box-shadow:0 6px 20px rgba(139,92,246,.4);font-size:16px}}
  .brand small{{display:block;font-weight:500;font-size:11px;color:var(--muted);letter-spacing:.3px}}
  .nav-meta{{display:flex;gap:18px;align-items:center;font-size:12px;color:var(--muted)}}
  .tag{{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border:1px solid var(--bd2);
    border-radius:999px;font-size:11.5px;color:var(--muted)}}
  .tag .gdot{{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green)}}
  .wrap{{max-width:1060px;margin:0 auto;padding:0 34px}}
  .hero{{padding:46px 0 14px}}
  h1{{font-size:30px;font-weight:800;letter-spacing:-.4px;line-height:1.15}}
  .hero p{{color:var(--muted);margin-top:10px;font-size:15px;max-width:760px}}
  .hero p b{{color:var(--tx)}}
  .hero p .hl{{color:var(--red);font-weight:700}}
  .kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:26px 0}}
  .kpi{{position:relative;background:linear-gradient(180deg,var(--panel2),var(--panel));
    border:1px solid var(--bd);border-radius:16px;padding:18px 18px 16px;overflow:hidden;
    transition:transform .15s ease,border-color .15s ease}}
  .kpi:hover{{transform:translateY(-2px);border-color:var(--bd2)}}
  .kpi .top{{height:3px;position:absolute;inset:0 0 auto 0;border-radius:16px 16px 0 0}}
  .kpi .v{{font-size:34px;font-weight:800;letter-spacing:-1px;line-height:1}}
  .kpi .l{{color:var(--muted);font-size:12.5px;margin-top:8px;font-weight:500}}
  .kpi .s{{color:var(--dim);font-size:11px;margin-top:2px}}
  .badges{{display:flex;flex-wrap:wrap;gap:12px;margin:6px 0 26px}}
  .badge{{display:inline-flex;align-items:center;gap:9px;padding:11px 16px;border-radius:13px;
    font-weight:650;font-size:13.5px;color:var(--c);
    background:color-mix(in srgb,var(--c) 12%,transparent);border:1px solid color-mix(in srgb,var(--c) 42%,transparent)}}
  .badge .dot{{width:9px;height:9px;border-radius:50%;background:var(--c);box-shadow:0 0 10px var(--c)}}
  .badge-sub{{color:var(--muted);font-weight:500;font-size:11.5px;margin-left:4px}}
  .grid3{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:26px}}
  .card{{background:var(--panel);border:1px solid var(--bd);border-radius:16px;padding:18px}}
  .card h3{{font-size:12px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);
    font-weight:650;margin-bottom:14px}}
  .bar-row{{display:grid;grid-template-columns:1fr 90px 26px;align-items:center;gap:10px;margin:9px 0}}
  .bar-label{{font-size:12.5px;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
  .bar-track{{height:7px;background:rgba(255,255,255,.06);border-radius:99px;overflow:hidden}}
  .bar-fill{{height:100%;border-radius:99px}}
  .bar-val{{font-size:12px;color:var(--muted);text-align:right;font-variant-numeric:tabular-nums}}
  .sec-title{{font-size:13px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);
    font-weight:650;margin:4px 0 12px}}
  .table-wrap{{background:var(--panel);border:1px solid var(--bd);border-radius:16px;overflow:hidden}}
  table{{width:100%;border-collapse:collapse}}
  th,td{{text-align:left;padding:13px 16px;font-size:13px;vertical-align:top;border-bottom:1px solid var(--bd)}}
  th{{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.6px;
    background:rgba(255,255,255,.02);position:sticky;top:73px}}
  tr:last-child td{{border-bottom:none}}
  tbody tr{{transition:background .12s ease}}
  tbody tr:hover{{background:rgba(255,255,255,.025)}}
  .pill{{font-size:10.5px;font-weight:700;padding:4px 10px;border-radius:999px;text-transform:uppercase;letter-spacing:.4px}}
  .pill.allow{{background:rgba(52,211,153,.14);color:var(--green);border:1px solid rgba(52,211,153,.35)}}
  .pill.block{{background:rgba(251,113,133,.14);color:var(--red);border:1px solid rgba(251,113,133,.35)}}
  .mono{{font-family:"SF Mono",ui-monospace,"JetBrains Mono",Consolas,monospace;font-size:12.5px}}
  .dim{{color:var(--dim)}}
  .reason{{color:var(--muted);max-width:330px;font-size:12.5px}}
  .chip{{display:inline-flex;align-items:center;gap:4px;font-size:11px;padding:3px 8px;border-radius:7px;
    margin:2px 4px 2px 0;background:rgba(255,255,255,.05);border:1px solid var(--bd);color:var(--muted)}}
  .chip b{{color:var(--tx);font-weight:700}}
  .chip-red{{color:var(--yellow);border-color:rgba(251,191,36,.3)}}
  .sev-critical{{color:var(--red);border-color:rgba(251,113,133,.4);background:rgba(251,113,133,.08)}}
  .sev-high{{color:var(--amber);border-color:rgba(245,158,11,.35);background:rgba(245,158,11,.08)}}
  .sev-warning{{color:var(--yellow);border-color:rgba(251,191,36,.3)}}
  footer{{color:var(--dim);font-size:12px;margin-top:34px;text-align:center;line-height:1.8}}
  footer b{{color:var(--muted)}}
  @media(max-width:880px){{.kpis{{grid-template-columns:repeat(2,1fr)}}.grid3{{grid-template-columns:1fr}}
    .nav-meta{{display:none}}.wrap{{padding:0 18px}}.nav{{padding:16px 18px}}}}
</style></head><body>

  <div class="nav">
    <div class="brand"><span class="logo">&#128737;</span>
      <div>AgentGate<small>Control Plane Report</small></div>
    </div>
    <div class="nav-meta">
      <span class="tag"><span class="gdot"></span>self-hosted · zero egress</span>
      <span>Generated {generated}</span>
    </div>
  </div>

  <div class="wrap">
    <div class="hero">
      <h1>Every tool call, governed.</h1>
      <p>Across this batch of agent tool calls, AgentGate
        redacted <span class="hl">{secrets_redacted}</span> secret(s) and
        <span class="hl">{pii_redacted}</span> PII value(s),
        blocked <span class="hl">{len(blocked)}</span> unauthorized / destructive call(s),
        held <span class="hl">{held}</span> for human approval,
        and flagged <span class="hl">{safety_flags}</span> safety risk(s) —
        all on a tamper-evident, externally-anchorable audit chain.
        <b>Generated entirely on your machine. Nothing left.</b></p>
    </div>

    <div class="kpis">
      <div class="kpi"><div class="top" style="background:var(--green)"></div>
        <div class="v" style="color:var(--green)">{len(allowed)}</div>
        <div class="l">Allowed</div><div class="s">passed every gate</div></div>
      <div class="kpi"><div class="top" style="background:var(--red)"></div>
        <div class="v" style="color:var(--red)">{len(blocked)}</div>
        <div class="l">Blocked</div><div class="s">policy · safety · limits</div></div>
      <div class="kpi"><div class="top" style="background:var(--yellow)"></div>
        <div class="v" style="color:var(--yellow)">{secrets_redacted + pii_redacted}</div>
        <div class="l">Redactions</div><div class="s">{secrets_redacted} secrets · {pii_redacted} PII</div></div>
      <div class="kpi"><div class="top" style="background:var(--blue)"></div>
        <div class="v">{total}</div>
        <div class="l">Total calls</div><div class="s">{span}</div></div>
    </div>

    <div class="badges">
      <div class="badge" style="--c:{chain_color}">
        <span class="dot"></span>{chain_icon}
        <span class="badge-sub">{_esc(chain_msg)}</span>
      </div>{anchor_block}
    </div>

    <div class="grid3">
      <div class="card"><h3>Blocks by reason</h3>{blocks_bars}</div>
      <div class="card"><h3>Calls by tool</h3>{tools_bars}</div>
      <div class="card"><h3>Safety findings</h3>{sev_bars}</div>
    </div>

    <div class="sec-title">Activity</div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Decision</th><th>Tool</th><th>Principal</th><th>Reason</th>
          <th>Redactions</th><th>Safety</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>

    <footer>
      <b>AgentGate v0.2</b> — self-hosted AI agent control plane<br>
      policy · redaction · rate-limit &amp; budget · human-in-the-loop approval · alerts ·
      hash-chained &amp; externally-anchored audit · observability
    </footer>
  </div>
</body></html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path
