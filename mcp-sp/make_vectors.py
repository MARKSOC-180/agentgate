#!/usr/bin/env python3
"""
make_vectors.py — generate the MCP-SP conformance vectors (pure stdlib, no deps).

These fixtures are the shared ground truth every MCP-SP implementation should agree
on. Run `python make_vectors.py` to (re)generate conformance_vectors/ and its
manifest. The standalone validator (mcp_sp.py) — and any third-party implementation
— must produce the level recorded in conformance_vectors/vectors.json for each.
"""

from __future__ import annotations

import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "conformance_vectors")


def _canonical(body: dict) -> str:
    return json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)


def _hash(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + "|" + _canonical(body)).encode("utf-8")).hexdigest()


def make_audit(rows, with_safety=True, identities=None) -> list:
    """rows: list of (tool, principal, decision). Returns chained records.

    identities: optional list aligned to rows; each entry is an identity dict
    (per SPEC §2.10) or None. Lets us build vectors that exercise the optional
    identity/delegation context.
    """
    out, prev = [], "GENESIS"
    for i, (tool, principal, decision) in enumerate(rows):
        body = {
            "ts": 1_700_000_000 + i,
            "tool": tool,
            "principal": principal,
            "decision": decision,
            "reasons": ["allowed by policy"] if decision == "allow" else ["blocked by policy"],
            "redaction_hits": {"email": 1} if i == 0 else {},
            "input_sha256": hashlib.sha256(f"in{i}".encode()).hexdigest()[:16],
            "output_sha256": hashlib.sha256(f"out{i}".encode()).hexdigest()[:16],
            "duration_ms": 1.5,
            "prev_hash": prev,
        }
        if with_safety:
            body["safety"] = []
        if identities and identities[i] is not None:
            body["identity"] = identities[i]
        this_hash = _hash(prev, body)
        out.append({**body, "this_hash": this_hash})
        prev = this_hash
    return out


def make_anchors(records, counts) -> list:
    """Anchor the audit chain at each record count in `counts`."""
    out, prev = [], "ANCHOR_GENESIS"
    for j, count in enumerate(counts):
        body = {
            "ts": 1_700_000_500 + j,
            "count": count,
            "audit_head": records[count - 1]["this_hash"],
            "prev_anchor": prev,
        }
        anchor_hash = _hash(prev, body)
        out.append({**body, "anchor_hash": anchor_hash})
        prev = anchor_hash
    return out


def write_ndjson(path, rows):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main():
    os.makedirs(OUT, exist_ok=True)
    manifest = {}

    base_rows = [("read_record", "agent-csr", "allow"),
                 ("delete_records", "agent-csr", "block")]

    # Level 1: valid chain but NO safety field -> Baseline only
    l1 = make_audit(base_rows, with_safety=False)
    write_ndjson(os.path.join(OUT, "valid_level1.ndjson"), l1)
    manifest["valid_level1.ndjson"] = {"anchors": None, "expected_level": 1}

    # Level 2: valid chain WITH safety field, no anchors -> Governed
    l2 = make_audit(base_rows, with_safety=True)
    write_ndjson(os.path.join(OUT, "valid_level2.ndjson"), l2)
    manifest["valid_level2.ndjson"] = {"anchors": None, "expected_level": 2}

    # Level 3: Level 2 audit + verifying anchors -> Assured
    write_ndjson(os.path.join(OUT, "valid_level3.audit.ndjson"), l2)
    anchors = make_anchors(l2, [2])
    write_ndjson(os.path.join(OUT, "valid_level3.anchors.ndjson"), anchors)
    manifest["valid_level3.audit.ndjson"] = {"anchors": "valid_level3.anchors.ndjson",
                                             "expected_level": 3}

    # Tampered: alter a field without recomputing the hash -> chain breaks -> Level 0
    tampered = [dict(r) for r in l2]
    tampered[0]["tool"] = "HACKED"
    write_ndjson(os.path.join(OUT, "tampered.ndjson"), tampered)
    manifest["tampered.ndjson"] = {"anchors": None, "expected_level": 0}

    # Missing field: drop a required field -> schema fails -> Level 0
    missing = [dict(r) for r in l2]
    del missing[1]["input_sha256"]
    write_ndjson(os.path.join(OUT, "missing_field.ndjson"), missing)
    manifest["missing_field.ndjson"] = {"anchors": None, "expected_level": 0}

    # Bad anchor: anchor head doesn't match the audit chain -> L3 fails -> Level 2
    write_ndjson(os.path.join(OUT, "bad_anchor.audit.ndjson"), l2)
    bad = make_anchors(l2, [2])
    bad[0]["audit_head"] = "deadbeef" * 8           # forged head
    bad[0]["anchor_hash"] = _hash("ANCHOR_GENESIS",
                                  {k: v for k, v in bad[0].items() if k != "anchor_hash"})
    write_ndjson(os.path.join(OUT, "bad_anchor.anchors.ndjson"), bad)
    manifest["bad_anchor.audit.ndjson"] = {"anchors": "bad_anchor.anchors.ndjson",
                                          "expected_level": 2}

    # Identity (§2.10): valid delegation chain, consistent -> still Level 2
    good_ident = [
        {"subject": "user-42", "actor": "agent-csr",
         "delegation": ["agent-csr", "user-42"], "granted": ["read:customer"]},
        {"subject": "user-42", "actor": "agent-csr",
         "delegation": ["agent-csr", "user-42"], "granted": ["read:customer"]},
    ]
    l2_id = make_audit(base_rows, with_safety=True, identities=good_ident)
    write_ndjson(os.path.join(OUT, "valid_identity_level2.ndjson"), l2_id)
    manifest["valid_identity_level2.ndjson"] = {"anchors": None, "expected_level": 2}

    # Bad identity: subject doesn't match the delegation tail -> integrity fail -> Level 0
    bad_ident = [
        {"subject": "attacker", "actor": "agent-csr",
         "delegation": ["agent-csr", "user-42"], "granted": ["read:customer"]},
        None,
    ]
    bad_id = make_audit(base_rows, with_safety=True, identities=bad_ident)
    write_ndjson(os.path.join(OUT, "bad_identity.ndjson"), bad_id)
    manifest["bad_identity.ndjson"] = {"anchors": None, "expected_level": 0}

    # Three-hop delegation (service → agent → user): valid chain -> Level 2
    triple_ident = [
        {"subject": "user-42", "actor": "service-plat",
         "delegation": ["service-plat", "agent-csr", "user-42"],
         "granted": ["read:customer", "refund:create"]},
        {"subject": "user-42", "actor": "service-plat",
         "delegation": ["service-plat", "agent-csr", "user-42"],
         "granted": ["read:customer"]},
    ]
    triple_rows = [("read_customer", "service-plat", "allow"),
                   ("issue_refund", "service-plat", "block")]
    l2_triple = make_audit(triple_rows, with_safety=True, identities=triple_ident)
    write_ndjson(os.path.join(OUT, "valid_identity_triple_level2.ndjson"), l2_triple)
    manifest["valid_identity_triple_level2.ndjson"] = {"anchors": None, "expected_level": 2}

    # Three-hop but actor ≠ delegation[0] (forged initiator) -> Level 0
    bad_triple = [
        {"subject": "user-42", "actor": "agent-csr",
         "delegation": ["service-plat", "agent-csr", "user-42"],
         "granted": ["read:customer"]},
        None,
    ]
    bad_triple_log = make_audit(triple_rows, with_safety=True, identities=bad_triple)
    write_ndjson(os.path.join(OUT, "bad_identity_triple.ndjson"), bad_triple_log)
    manifest["bad_identity_triple.ndjson"] = {"anchors": None, "expected_level": 0}

    # §2.4/§2.5 optional extensions: valid limits + approval metadata -> Level 2
    gov_rows = [("read_record", "agent", "allow"), ("delete_records", "agent", "block")]
    gov_ext = [
        {"limits": {"checked": True, "cost": 0.0}},
        {"approval": {"id": "appr-001", "status": "pending"}},
    ]

    def make_audit_ext(rows, extensions):
        out, prev = [], "GENESIS"
        for i, (tool, principal, decision) in enumerate(rows):
            body = {
                "ts": 1_700_000_000 + i, "tool": tool, "principal": principal,
                "decision": decision,
                "reasons": ["ok"] if decision == "allow" else ["blocked"],
                "redaction_hits": {}, "safety": [],
                "input_sha256": "a", "output_sha256": "b", "duration_ms": 1.0,
                "prev_hash": prev,
            }
            ext = extensions[i] if extensions else {}
            if ext.get("limits"):
                body["limits"] = ext["limits"]
            if ext.get("approval"):
                body["approval"] = ext["approval"]
            this = _hash(prev, body)
            out.append({**body, "this_hash": this})
            prev = this
        return out

    l2_ext = make_audit_ext(gov_rows, gov_ext)
    write_ndjson(os.path.join(OUT, "valid_governed_extensions_level2.ndjson"), l2_ext)
    manifest["valid_governed_extensions_level2.ndjson"] = {"anchors": None, "expected_level": 2}

    bad_ext = make_audit_ext(gov_rows, [{"limits": {"no_checked_key": True}}, {}])
    write_ndjson(os.path.join(OUT, "bad_limits.ndjson"), bad_ext)
    manifest["bad_limits.ndjson"] = {"anchors": None, "expected_level": 0}

    bad_appr = make_audit_ext(gov_rows, [{}, {"approval": {"id": "appr-bad", "status": "maybe"}}])
    write_ndjson(os.path.join(OUT, "bad_approval.ndjson"), bad_appr)
    manifest["bad_approval.ndjson"] = {"anchors": None, "expected_level": 0}

    with open(os.path.join(OUT, "vectors.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print(f"wrote {len(manifest)} vectors + manifest to {OUT}")


if __name__ == "__main__":
    main()
