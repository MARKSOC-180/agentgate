#!/usr/bin/env python3
"""
mcp_sp.py — MCP Security Profile (MCP-SP) reference validator.

A SINGLE-FILE, ZERO-DEPENDENCY conformance checker for the MCP Security Profile.
It does NOT depend on AgentGate or any package — copy this one file into any repo,
or run it directly, and self-certify your MCP-SP level in one command:

    python mcp_sp.py path/to/audit.ndjson --anchors path/to/anchors.ndjson --require 3

It validates an audit log produced per MCP-SP SPEC.md §3 and reports the level:

    Level 1 (Baseline) : §2.1 policy + §2.2 redaction + §2.6 tamper-evident audit
    Level 2 (Governed) : Level 1 + §2.3 safety
    Level 3 (Assured)  : Level 2 + §2.7 external anchoring

It prints a PASS/FAIL line per control and a ready-to-paste badge. `--require N`
exits non-zero below level N, so it drops straight into CI as a gate.

This file is the normative reference checker for the profile. Any implementation,
in any language, may reproduce its behavior; the conformance_vectors/ directory
contains fixtures every implementation should agree on.

License: Apache-2.0.  Spec: ./SPEC.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from urllib.parse import quote

SPEC_VERSION = "MCP-SP/0.2"

# SPEC §3 — required audit-record fields (the Level 1 hard gate).
REQUIRED_FIELDS = ["ts", "tool", "principal", "decision", "reasons",
                   "redaction_hits", "input_sha256", "output_sha256",
                   "prev_hash", "this_hash"]

_BADGE_COLOR = {0: "red", 1: "yellow", 2: "blue", 3: "brightgreen"}
_LEVEL_NAME = {0: "not conformant", 1: "Baseline", 2: "Governed", 3: "Assured"}
SPEC_URL = "https://github.com/agentgate/agentgate/blob/main/SPEC.md"


# ---- canonicalization (SPEC §3) ------------------------------------------------
def _canonical(body: dict) -> str:
    """canonical(body): JSON with sorted keys (matches the reference serialization)."""
    return json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)


def _hash(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + "|" + _canonical(body)).encode("utf-8")).hexdigest()


def _load(path: str) -> list:
    out = []
    if not path or not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


# ---- checks --------------------------------------------------------------------
def _verify_audit_chain(records: list) -> tuple:
    prev = "GENESIS"
    for i, rec in enumerate(records, 1):
        claimed = rec.get("this_hash")
        body = {k: v for k, v in rec.items() if k != "this_hash"}
        if body.get("prev_hash") != prev:
            return False, f"record #{i}: prev_hash breaks the chain (deleted/inserted?)"
        if _hash(prev, body) != claimed:
            return False, f"record #{i}: hash mismatch (tampered, or non-canonical hashing?)"
        prev = claimed
    return True, f"chain intact, {len(records)} records, no tampering"


def _verify_anchor_chain(anchors: list) -> tuple:
    prev = "ANCHOR_GENESIS"
    for i, rec in enumerate(anchors, 1):
        body = {k: v for k, v in rec.items() if k != "anchor_hash"}
        if body.get("prev_anchor") != prev:
            return False, f"anchor #{i}: broken anchor chain (prev mismatch)"
        if _hash(prev, body) != rec.get("anchor_hash"):
            return False, f"anchor #{i}: anchor hash mismatch (tampered)"
        prev = rec["anchor_hash"]
    return True, f"anchor chain intact, {len(anchors)} anchors"


def _verify_identity(records: list) -> tuple:
    """§2.10 — verify any present identity/delegation context is self-consistent.

    Identity is an OPTIONAL extension: logs without it are unaffected. But when a
    record DOES carry `identity`, it MUST be structurally sound — the recorded
    delegation chain must agree with the claimed actor/subject, and grants must be a
    sorted list of scope strings — otherwise the evidence is not trustworthy.
    """
    seen = 0
    for i, r in enumerate(records, 1):
        ident = r.get("identity")
        if ident is None:
            continue
        seen += 1
        if not isinstance(ident, dict):
            return False, f"record #{i}: identity must be an object", seen
        chain = ident.get("delegation")
        if not isinstance(chain, list) or not chain:
            return False, f"record #{i}: identity.delegation must be a non-empty list", seen
        if ident.get("actor") != chain[0]:
            return False, f"record #{i}: identity.actor must equal delegation[0]", seen
        if ident.get("subject") != chain[-1]:
            return False, f"record #{i}: identity.subject must equal delegation[-1] (whom the action is for)", seen
        granted = ident.get("granted")
        if not isinstance(granted, list) or any(not isinstance(g, str) for g in granted):
            return False, f"record #{i}: identity.granted must be a list of scope strings", seen
        if list(granted) != sorted(granted):
            return False, f"record #{i}: identity.granted must be sorted (canonical effective grants)", seen
    if seen == 0:
        return True, "no identity context present (optional §2.10)", 0
    return True, f"{seen} record(s) carry a consistent identity/delegation context", seen


def _verify_limits_approval(records: list) -> tuple:
    """§2.4 / §2.5 — optional audit extensions: when present, must be well-formed."""
    lim_seen = appr_seen = 0
    for i, r in enumerate(records, 1):
        lim = r.get("limits")
        if lim is not None:
            lim_seen += 1
            if not isinstance(lim, dict) or "checked" not in lim:
                return False, f"record #{i}: limits must be an object with checked", lim_seen, appr_seen
        appr = r.get("approval")
        if appr is not None:
            appr_seen += 1
            if not isinstance(appr, dict):
                return False, f"record #{i}: approval must be an object", lim_seen, appr_seen
            if not isinstance(appr.get("id"), str):
                return False, f"record #{i}: approval.id must be a string", lim_seen, appr_seen
            if appr.get("status") not in ("pending", "approved", "denied"):
                return False, f"record #{i}: approval.status invalid", lim_seen, appr_seen
    if lim_seen == 0 and appr_seen == 0:
        return True, "no limits/approval extensions (optional §2.4/§2.5)", 0, 0
    parts = []
    if lim_seen:
        parts.append(f"{lim_seen} limits")
    if appr_seen:
        parts.append(f"{appr_seen} approval")
    return True, f"{', '.join(parts)} record(s) well-formed", lim_seen, appr_seen


def _verify_anchors(audit_records: list, anchors: list) -> tuple:
    if not anchors:
        return False, "anchors file is empty; Level 3 requires at least one verified anchor"
    ok, msg = _verify_anchor_chain(anchors)
    if not ok:
        return False, msg
    running = [r.get("this_hash") for r in audit_records]
    for i, a in enumerate(anchors, 1):
        count = a.get("count", 0)
        if count == 0:
            continue
        if count > len(running):
            return False, (f"anchor #{i} expects >= {count} audit records "
                           f"but found {len(running)} (records deleted/truncated)")
        if running[count - 1] != a.get("audit_head"):
            return False, (f"anchor #{i} (count={count}): audit head changed "
                           f"since anchoring — history was rewritten")
    return True, f"verified against {len(anchors)} anchor(s); history intact"


def badge_markdown(level: int) -> str:
    color = _BADGE_COLOR.get(level, "red")
    label = quote(f"Level {level}") if level else quote("not conformant")
    return (f"[![MCP-SP](https://img.shields.io/badge/MCP--SP-{label}-{color})]"
            f"({SPEC_URL})")


def check(audit_path: str, anchors_path: str = None,
          self_hosted: bool = False) -> dict:
    """Validate an MCP-SP audit log and determine its conformance level (0–3)."""
    records = _load(audit_path)
    passed, failed = [], []

    if not records:
        failed.append("Audit log is empty — cannot demonstrate any control")
        return _result(0, passed, failed, self_hosted, audit_path)

    # Level 1 / Baseline
    schema_ok = True
    for i, r in enumerate(records, 1):
        missing = [f for f in REQUIRED_FIELDS if f not in r]
        if missing:
            schema_ok = False
            failed.append(f"§3 record #{i} missing required field(s): {', '.join(missing)}")
            break
    if schema_ok:
        passed.append("§3 Audit-record schema: all required fields present")

    decisions_ok = all(r.get("decision") in ("allow", "block") for r in records)
    (passed if decisions_ok else failed).append(
        "§2.1 Policy: every record carries a decision of allow|block"
        if decisions_ok else "§2.1 Policy: a record's decision is not allow|block")

    redaction_ok = all(isinstance(r.get("redaction_hits"), dict) for r in records)
    (passed if redaction_ok else failed).append(
        "§2.2 Redaction: every record records redaction hits"
        if redaction_ok else "§2.2 Redaction: a record is missing a redaction_hits map")

    chain_ok, chain_msg = _verify_audit_chain(records)
    (passed if chain_ok else failed).append("§2.6 Tamper-evident audit: " + chain_msg)

    identity_ok, identity_msg, _ = _verify_identity(records)
    (passed if identity_ok else failed).append("§2.10 Identity & delegation: " + identity_msg)

    lim_ok, lim_msg, _, _ = _verify_limits_approval(records)
    (passed if lim_ok else failed).append("§2.4/§2.5 Limits & approval: " + lim_msg)

    level1 = schema_ok and decisions_ok and redaction_ok and chain_ok and identity_ok and lim_ok

    # Level 2 / Governed
    safety_ok = all("safety" in r for r in records)
    (passed if safety_ok else failed).append(
        "§2.3 Safety: every record carries a safety findings field"
        if safety_ok else "§2.3 Safety: a record is missing the safety field")
    level2 = level1 and safety_ok

    # Level 3 / Assured
    if anchors_path:
        anchored_ok, a_msg = _verify_anchors(records, _load(anchors_path))
        (passed if anchored_ok else failed).append("§2.7 External anchoring: " + a_msg)
    else:
        anchored_ok = False
        failed.append("§2.7 External anchoring: no anchors file provided (required for Level 3)")
    level3 = level2 and anchored_ok

    level = 3 if level3 else 2 if level2 else 1 if level1 else 0
    return _result(level, passed, failed, self_hosted, audit_path)


def _result(level, passed, failed, self_hosted, audit_path) -> dict:
    return {
        "spec": SPEC_VERSION,
        "level": level,
        "level_name": _LEVEL_NAME[level],
        "passed": passed,
        "failed": failed,
        "declared": {"selfHosted": bool(self_hosted)},
        "badge": badge_markdown(level),
        "audit_path": audit_path,
    }


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    p = argparse.ArgumentParser(
        prog="mcp_sp",
        description="MCP Security Profile (MCP-SP) reference validator — single file, zero deps.")
    p.add_argument("audit", help="path to the MCP-SP audit log (NDJSON, per SPEC §3)")
    p.add_argument("--anchors", default=None, help="path to the anchor log (required for Level 3)")
    p.add_argument("--require", type=int, default=None, choices=[1, 2, 3],
                   help="minimum required level; exit non-zero if not met (CI gate)")
    p.add_argument("--self-hosted", action="store_true", help="declare self-hosted (§2.9)")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = p.parse_args(argv)

    res = check(args.audit, anchors_path=args.anchors, self_hosted=args.self_hosted)

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(f"MCP-SP conformance: Level {res['level']} ({res['level_name']})")
        for m in res["passed"]:
            print(f"  PASS  {m}")
        for m in res["failed"]:
            print(f"  ---   {m}")
        print("\nBadge (paste into your README):")
        print("  " + res["badge"])

    met = res["level"] >= (args.require or 1)
    if args.require:
        if not args.json:
            print(f"\nRequired Level {args.require}: {'OK' if met else 'NOT MET'}")
        return 0 if met else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
