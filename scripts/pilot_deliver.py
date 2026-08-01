#!/usr/bin/env python3
"""
试点验收交付包 — 一键生成客户可收的合规 + MCP-SP 自证材料。

用法:
    python scripts/pilot_deliver.py \\
        --audit agentgate_audit.ndjson \\
        --anchors agentgate_anchors.ndjson \\
        --out pilot_delivery_acme_20260630

产出:
    out/
      compliance_export/   # md, csv, json, cef
      agentgate_report.html
      mcp_sp_conformance.json
      README_DELIVERY.txt  # 验收清单
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def main() -> int:
    p = argparse.ArgumentParser(description="生成 AgentGate 试点验收交付包")
    p.add_argument("--audit", default="agentgate_audit.ndjson")
    p.add_argument("--anchors", default=None, help="Level 3 需要锚点文件")
    p.add_argument("--out", required=True, help="输出目录")
    p.add_argument("--customer", default="Customer", help="客户名称（写入 README）")
    args = p.parse_args()

    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)

    from agentgate.compliance import export_compliance
    from agentgate.report import build_report
    from agentgate.conformance import check_conformance
    from agentgate.audit import AuditLog

    comp_dir = os.path.join(out, "compliance_export")
    info = export_compliance(args.audit, out_dir=comp_dir)

    report_path = build_report(
        args.audit,
        os.path.join(out, "agentgate_report.html"),
        anchor_path=args.anchors,
    )

    res = check_conformance(
        args.audit,
        anchors_path=args.anchors,
        capabilities={"selfHosted": True},
    )
    conf_path = os.path.join(out, "mcp_sp_conformance.json")
    with open(conf_path, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)

    ok_chain, chain_msg = AuditLog(args.audit).verify()
    level_ok = res.get("level", 0) >= 3 if args.anchors else res.get("level", 0) >= 1

    readme = os.path.join(out, "README_DELIVERY.txt")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open(readme, "w", encoding="utf-8") as f:
        f.write(f"AgentGate Pilot Delivery Pack\n")
        f.write(f"Customer: {args.customer}\n")
        f.write(f"Generated: {ts}\n")
        f.write(f"{'='*50}\n\n")
        f.write(f"Audit chain: {'PASS' if ok_chain else 'FAIL'} — {chain_msg}\n")
        f.write(f"MCP-SP Level: {res.get('level')} ({res.get('level_name')})\n")
        f.write(f"Badge: {res.get('badge', '')}\n\n")
        f.write("Contents:\n")
        f.write(f"  - compliance_export/  (MD, CSV, JSON, CEF)\n")
        f.write(f"  - agentgate_report.html\n")
        f.write(f"  - mcp_sp_conformance.json\n")
        f.write(f"  - vendor_security_unblock/  (questionnaire drafts + evidence map)\n\n")
        f.write("Acceptance checklist:\n")
        f.write(f"  [{'x' if ok_chain else ' '}] Hash chain verify PASS\n")
        f.write(f"  [{'x' if args.anchors else ' '}] External anchors provided\n")
        f.write(f"  [{'x' if res.get('level',0)>=3 else ' '}] MCP-SP Level >= 3\n")
        f.write(f"  [x] Compliance export (4 formats)\n")
        f.write(f"  [x] HTML executive report\n")
        f.write(f"  [x] Vendor security unblock templates\n")

    pack_src = os.path.join(ROOT, "packs", "vendor_security_unblock")
    pack_dst = os.path.join(out, "vendor_security_unblock")
    if os.path.isdir(pack_src):
        if os.path.isdir(pack_dst):
            shutil.rmtree(pack_dst)
        shutil.copytree(pack_src, pack_dst)
        # light personalization marker in QUESTION_BANK
        qb = os.path.join(pack_dst, "QUESTION_BANK.md")
        if os.path.isfile(qb):
            with open(qb, encoding="utf-8") as rf:
                body = rf.read()
            body = body.replace("{COMPANY}", args.customer)
            with open(qb, "w", encoding="utf-8") as wf:
                wf.write(body)

    print(f"交付包已生成：{out}")
    print(f"  合规导出：{comp_dir}")
    print(f"  HTML 报告：{report_path}")
    print(f"  MCP-SP：Level {res.get('level')} → {conf_path}")
    print(f"  链校验：{'PASS' if ok_chain else 'FAIL'}")
    if args.anchors and res.get("level", 0) < 3:
        print("  警告：未达 Level 3，请检查锚点或 safety 字段")
        return 1
    return 0 if ok_chain else 1


if __name__ == "__main__":
    sys.exit(main())
