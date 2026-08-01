"""
cli.py —— AgentGate 统一命令行入口。

安装后即可使用(pip install -e .)：
    agentgate proxy  --config agentgate.config.json     # 把控制平面挡在任意 MCP server 前
    agentgate verify [审计文件]                          # 校验哈希链是否被篡改
    agentgate export [审计文件] --out compliance_export  # 导出合规包(Markdown + CSV)
    agentgate report [审计文件] --out report.html        # 生成 HTML 报告
    agentgate version
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from . import __version__


def _cmd_proxy(args) -> int:
    from .mcp_proxy import main as proxy_main
    passthrough = []
    if args.config:
        passthrough += ["--config", args.config]
    if args.downstream:
        passthrough += ["--downstream", args.downstream]
    return proxy_main(passthrough)


def _cmd_verify(args) -> int:
    from .audit import AuditLog
    audit = AuditLog(args.audit)
    ok, msg = audit.verify()
    print(("PASS ✅ " if ok else "FAIL ❌ ") + msg)
    if args.anchors:
        from .anchoring import Anchor
        a_ok, a_msg = Anchor(args.anchors).verify(audit)
        print(("ANCHOR PASS ✅ " if a_ok else "ANCHOR FAIL ❌ ") + a_msg)
        ok = ok and a_ok
    return 0 if ok else 1


def _cmd_anchor(args) -> int:
    from .audit import AuditLog
    from .anchoring import Anchor
    rec = Anchor(args.out).anchor(AuditLog(args.audit))
    print(f"已锚定 ✅ count={rec['count']} head={rec['audit_head'][:16]}… → {args.out}")
    return 0


def _cmd_export(args) -> int:
    from .compliance import export_compliance
    info = export_compliance(args.audit, out_dir=args.out)
    print(f"合规包已生成：{info['report_path']} / {info['csv_path']} / "
          f"{info['json_path']} / {info['cef_path']}")
    print(("链校验 PASS ✅ " if info["chain_ok"] else "链校验 FAIL ❌ ") + info["chain_msg"])
    return 0 if info["chain_ok"] else 1


def _cmd_report(args) -> int:
    from .report import build_report
    out = build_report(args.audit, args.out, anchor_path=args.anchors)
    print(f"HTML 报告已生成：{out}")
    return 0


def _cmd_metrics(args) -> int:
    from .metrics import prometheus_text
    text = prometheus_text(args.audit)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"指标已写入：{args.out}")
    else:
        sys.stdout.write(text)
    return 0


def _cmd_usage(args) -> int:
    from .metering import Pricing, usage_report, billing_csv
    pricing = Pricing(price_per_call=args.price, included_calls=args.free)
    rep = usage_report(args.audit, pricing, by=args.by)
    cur = rep["pricing"]["currency"]
    print(f"用量账单（按 {rep['by']}，源自不可篡改审计链，可验证）")
    print(f"{'KEY':<22}{'calls':>8}{'billable':>10}{'charged':>9}{'amount':>12}")
    for key, r in sorted(rep["rows"].items(), key=lambda kv: -kv[1]["amount"]):
        print(f"{str(key)[:22]:<22}{r['calls']:>8}{r['billable']:>10}"
              f"{r['billable_charged']:>9}{r['amount']:>11.4f}{cur:>1}")
    t = rep["totals"]
    print(f"{'TOTAL':<22}{t['calls']:>8}{t['billable']:>10}{'':>9}{t['amount']:>11.4f}{cur:>1}")
    if args.csv:
        billing_csv(rep, args.csv)
        print(f"账单 CSV 已导出：{args.csv}")
    return 0


def _cmd_conformance(args) -> int:
    from .conformance import check_conformance
    res = check_conformance(args.audit, anchors_path=args.anchors,
                            capabilities={"selfHosted": args.self_hosted})
    ok = res["level"] >= (args.require or 1)
    if args.json:
        import json as _json
        print(_json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if ok else 1
    if args.badge_only:
        print(res["badge"])
        return 0 if ok else 1
    print(f"MCP-SP conformance: Level {res['level']} ({res['level_name']})")
    for p in res["passed"]:
        print(f"  PASS  {p}")
    for fmsg in res["failed"]:
        print(f"  ---   {fmsg}")
    print("\nBadge (paste into your README):")
    print("  " + res["badge"])
    if args.require:
        print(f"\nRequired Level {args.require}: {'OK' if ok else 'NOT MET'}")
    return 0 if ok else 1


def _cmd_intel(args) -> int:
    from .intel import ThreatIntel
    ti = ThreatIntel(args.path)
    if args.export:
        import json as _json
        feed = ti.export_feed()
        with open(args.export, "w", encoding="utf-8") as f:
            _json.dump(feed, f, ensure_ascii=False, indent=2)
        print(f"匿名情报源已导出：{args.export}（{feed['events']} 事件，可贡献给共享网络）")
        return 0
    s = ti.summarize()
    print(f"威胁情报汇总（{s['events']} 个事件，其中 {s['blocks']} 次拦截）")
    print("Top 攻击签名：")
    for sig, n in s["top_threats"]:
        print(f"  {n:>5}  {sig}")
    if s["by_severity"]:
        print("按严重度：" + ", ".join(f"{k}={v}" for k, v in s["by_severity"].items()))
    return 0


def _cmd_approvals(args) -> int:
    from .approvals import ApprovalStore
    store = ApprovalStore(args.store)
    if args.action == "list":
        rows = store.pending() if args.pending else store.all()
        if not rows:
            print("(无审批记录)")
            return 0
        for r in rows:
            print(f"{r['id']}  [{r['status']:<8}]  {r['tool']}  "
                  f"principal={r['principal']}  {r.get('reason','')}")
        return 0
    if args.action in ("approve", "deny"):
        if not args.id:
            print("请提供 approval_id")
            return 2
        ok = (store.approve(args.id, args.approver) if args.action == "approve"
              else store.deny(args.id, args.approver))
        print(("已批准 ✅ " if args.action == "approve" else "已拒绝 ⛔ ") + args.id
              if ok else f"操作失败：{args.id} 不存在或已被处理")
        return 0 if ok else 1
    return 2


def _cmd_version(_args) -> int:
    print(f"AgentGate {__version__}")
    return 0


def _cmd_start(args) -> int:
    """一个动作开始：生成配置 + Cursor 片段 + 下一步（藏起其余复杂度）。"""
    from .onboard import ensure_config, write_cursor_snippet, print_start_card

    cfg, created = ensure_config(args.config, downstream=args.downstream)
    snippet = write_cursor_snippet(cfg, args.snippet)
    print_start_card(cfg, snippet, created)
    if args.run:
        from .mcp_proxy import main as proxy_main
        return proxy_main(["--config", cfg])
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentgate",
        description="AgentGate — protect every tool call. On your machine.")
    sub = p.add_subparsers(dest="command", required=True)

    ss = sub.add_parser("start", help="One step: create config + Cursor snippet (Jobs-simple)")
    ss.add_argument("--config", default="agentgate.config.json", help="config path")
    ss.add_argument("--downstream", default=None,
                    help='your MCP server command, e.g. "python my_server.py"')
    ss.add_argument("--snippet", default="cursor.mcp.snippet.json",
                    help="Cursor MCP snippet output path")
    ss.add_argument("--run", action="store_true", help="start proxy immediately after init")
    ss.set_defaults(func=_cmd_start)

    sp = sub.add_parser("proxy", help="把控制平面挡在任意 MCP server 前(stdio 代理)")
    sp.add_argument("--config", help="JSON 配置文件路径")
    sp.add_argument("--downstream", help="下游 MCP server 启动命令(与 --config 二选一)")
    sp.set_defaults(func=_cmd_proxy)

    sv = sub.add_parser("verify", help="校验审计哈希链是否被篡改")
    sv.add_argument("audit", nargs="?", default="agentgate_audit.ndjson")
    sv.add_argument("--anchors", default=None, help="同时用外部锚点反查历史是否被重写")
    sv.set_defaults(func=_cmd_verify)

    san = sub.add_parser("anchor", help="对审计链当前状态打一个外部锚点")
    san.add_argument("audit", nargs="?", default="agentgate_audit.ndjson")
    san.add_argument("--out", default="agentgate_anchors.ndjson")
    san.set_defaults(func=_cmd_anchor)

    se = sub.add_parser("export", help="导出合规包(Markdown + CSV)")
    se.add_argument("audit", nargs="?", default="agentgate_audit.ndjson")
    se.add_argument("--out", default="compliance_export")
    se.set_defaults(func=_cmd_export)

    sr = sub.add_parser("report", help="生成自包含 HTML 报告")
    sr.add_argument("audit", nargs="?", default="agentgate_audit.ndjson")
    sr.add_argument("--out", default="agentgate_report.html")
    sr.add_argument("--anchors", default=None, help="在报告中展示外部锚定校验状态")
    sr.set_defaults(func=_cmd_report)

    sm = sub.add_parser("metrics", help="导出 Prometheus 指标")
    sm.add_argument("audit", nargs="?", default="agentgate_audit.ndjson")
    sm.add_argument("--out", default=None, help="写入文件(默认打印到 stdout)")
    sm.set_defaults(func=_cmd_metrics)

    su = sub.add_parser("usage", help="按调用量出账单(源自不可篡改审计链)")
    su.add_argument("audit", nargs="?", default="agentgate_audit.ndjson")
    su.add_argument("--price", type=float, default=0.002, help="每次调用单价")
    su.add_argument("--free", type=int, default=0, help="免费额度(按分组)")
    su.add_argument("--by", default="principal", choices=["principal", "tool"])
    su.add_argument("--csv", default=None, help="同时导出账单 CSV")
    su.set_defaults(func=_cmd_usage)

    sc = sub.add_parser("conformance", help="MCP-SP 一致性自检 + 生成徽章(任何实现者可用)")
    sc.add_argument("audit", nargs="?", default="agentgate_audit.ndjson")
    sc.add_argument("--anchors", default=None, help="锚点文件(Level 3 需要)")
    sc.add_argument("--require", type=int, default=None, choices=[1, 2, 3],
                    help="要求达到的最低等级(用于 CI 门禁，未达到则退出码非 0)")
    sc.add_argument("--self-hosted", action="store_true", help="声明自托管(§2.9)")
    sc.add_argument("--json", action="store_true", help="机器可读 JSON 输出")
    sc.add_argument("--badge-only", action="store_true", help="仅打印 README 徽章 Markdown")
    sc.set_defaults(func=_cmd_conformance)

    si = sub.add_parser("intel", help="威胁情报数据飞轮：汇总 / 导出匿名情报源")
    si.add_argument("path", nargs="?", default="agentgate_intel.ndjson")
    si.add_argument("--export", default=None, help="导出可共享的匿名聚合情报源(JSON)")
    si.set_defaults(func=_cmd_intel)

    sa = sub.add_parser("approvals", help="人在环审批：列出 / 批准 / 拒绝")
    sa.add_argument("action", choices=["list", "approve", "deny"])
    sa.add_argument("id", nargs="?", help="approval_id(approve/deny 时必填)")
    sa.add_argument("--pending", action="store_true", help="list 时只看待审批")
    sa.add_argument("--approver", default="human")
    sa.add_argument("--store", default="agentgate_approvals.json")
    sa.set_defaults(func=_cmd_approvals)

    sver = sub.add_parser("version", help="打印版本")
    sver.set_defaults(func=_cmd_version)
    return p


def main(argv: Optional[list] = None) -> int:
    # 跨平台：避免 Windows 默认 gbk 控制台无法输出 ✅/❌ 等字符而崩溃
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
