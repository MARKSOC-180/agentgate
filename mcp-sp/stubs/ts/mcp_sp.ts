#!/usr/bin/env node
/**
 * MCP-SP reference validator ? TypeScript port (zero npm deps at runtime).
 * Run: npx tsx mcp-sp/stubs/ts/mcp_sp.ts audit.ndjson [--anchors anchors.ndjson] [--require 3]
 * Or compile: tsc && node mcp_sp.js ...
 *
 * Must agree with mcp-sp/conformance_vectors/vectors.json (same bar as mcp_sp.py).
 */
import * as fs from "node:fs";
import * as crypto from "node:crypto";

const SPEC_VERSION = "MCP-SP/0.2";
const REQUIRED = ["ts","tool","principal","decision","reasons","redaction_hits",
  "input_sha256","output_sha256","prev_hash","this_hash"] as const;

function sortDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(o).sort()) out[k] = sortDeep(o[k]);
    return out;
  }
  return v;
}

function serialize(v: unknown, decimalPaths: Set<string>, path = ""): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (decimalPaths.has(path) && Number.isInteger(v)) return `${v}.0`;
    return String(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map((x, i) => serialize(x, decimalPaths, `${path}[${i}]`)).join(", ") + "]";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return "{" + Object.keys(o).sort()
      .map(k => JSON.stringify(k) + ": " + serialize(o[k], decimalPaths, path ? `${path}.${k}` : k)).join(", ") + "}";
  }
  return JSON.stringify(String(v));
}

function canonical(body: Record<string, unknown>, decimalPaths: Set<string> = new Set()): string {
  return serialize(sortDeep(body), decimalPaths);
}

function hash(prev: string, body: Record<string, unknown>, decimalPaths: Set<string> = new Set()): string {
  return crypto.createHash("sha256").update(prev + "|" + canonical(body, decimalPaths)).digest("hex");
}

/** ??? NDJSON ????? X.0 ??????????? Python json.dumps ??????? */
function floatDecimalPaths(raw: string): Set<string> {
  const paths = new Set<string>();
  const stack: string[] = [];
  let i = 0;
  const ws = () => { while (i < raw.length && /\s/.test(raw[i])) i++; };
  const readStr = (): string => {
    i++;
    const start = i;
    while (i < raw.length && raw[i] !== '"') { if (raw[i] === "\\") i++; i++; }
    const s = raw.slice(start, i);
    i++;
    return s;
  };
  const readNum = (): string => {
    const start = i;
    if (raw[i] === "-") i++;
    while (i < raw.length && /[\d.]/.test(raw[i])) i++;
    if (i < raw.length && (raw[i] === "e" || raw[i] === "E")) {
      i++;
      if (raw[i] === "+" || raw[i] === "-") i++;
      while (i < raw.length && /\d/.test(raw[i])) i++;
    }
    return raw.slice(start, i);
  };
  const skipVal = (): void => {
    ws();
    const c = raw[i];
    if (c === '"') { readStr(); return; }
    if (c === "{") { stack.push("__obj__"); i++; while (raw[i] !== "}") parseEntry(); i++; stack.pop(); return; }
    if (c === "[") { i++; ws(); while (raw[i] !== "]") { skipVal(); ws(); if (raw[i] === ",") i++; ws(); } i++; return; }
    if (c === "t") { i += 4; return; }
    if (c === "f") { i += 5; return; }
    if (c === "n") { i += 4; return; }
    readNum();
  };
  const parseEntry = (): void => {
    ws();
    if (raw[i] === "}") return;
    const key = readStr();
    ws();
    i++; // :
    ws();
    const childPath = [...stack.filter(s => s !== "__obj__" && s !== "__arr__"), key].join(".");
    const c = raw[i];
    if (c === "{") {
      stack.push(key);
      i++;
      while (raw[i] !== "}") { parseEntry(); ws(); if (raw[i] === ",") i++; }
      i++;
      stack.pop();
    } else if (c === "[") {
      skipVal();
    } else if (c === '"') {
      readStr();
    } else if (c === "t" || c === "f" || c === "n") {
      skipVal();
    } else {
      const lit = readNum();
      if (/^-?\d+\.0+$/.test(lit)) paths.add(childPath);
    }
  };
  ws();
  if (raw[i] === "{") { i++; while (raw[i] !== "}") { parseEntry(); ws(); if (raw[i] === ",") i++; } }
  return paths;
}

type LoadedLine = { record: Record<string, unknown>; decimalPaths: Set<string> };

function load(path: string): LoadedLine[] {
  if (!path || !fs.existsSync(path)) return [];
  return fs.readFileSync(path, "utf8").split("\n").filter(Boolean).map(line => ({
    record: JSON.parse(line) as Record<string, unknown>,
    decimalPaths: floatDecimalPaths(line),
  }));
}

function verifyChain(lines: LoadedLine[]): [boolean, string] {
  let prev = "GENESIS";
  for (let i = 0; i < lines.length; i++) {
    const { record: rec, decimalPaths } = lines[i];
    const claimed = rec.this_hash as string;
    const body = { ...rec }; delete (body as any).this_hash;
    if (body.prev_hash !== prev) return [false, `record #${i+1}: prev_hash breaks chain`];
    if (hash(prev, body as Record<string, unknown>, decimalPaths) !== claimed)
      return [false, `record #${i+1}: hash mismatch`];
    prev = claimed;
  }
  return [true, `chain intact, ${lines.length} records`];
}

function verifyIdentity(records: Record<string, unknown>[]): [boolean, string] {
  let seen = 0;
  for (let i = 0; i < records.length; i++) {
    const ident = recIdentity(records[i]); if (!ident) continue;
    seen++;
    const chain = ident.delegation as string[];
    if (!Array.isArray(chain) || !chain.length)
      return [false, `record #${i+1}: identity.delegation invalid`];
    if (ident.actor !== chain[0]) return [false, `record #${i+1}: actor != delegation[0]`];
    if (ident.subject !== chain[chain.length-1])
      return [false, `record #${i+1}: subject != delegation tail`];
    const g = ident.granted as string[];
    if (!Array.isArray(g) || g.join() !== [...g].sort().join())
      return [false, `record #${i+1}: granted must be sorted`];
  }
  return [true, seen ? `${seen} record(s) with consistent identity` : "no identity (optional)"];
}

function recIdentity(r: Record<string, unknown>) {
  return r.identity as Record<string, unknown> | undefined;
}

function verifyLimitsApproval(records: Record<string, unknown>[]): [boolean, string] {
  let lim = 0, appr = 0;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    const l = r.limits as Record<string, unknown> | undefined;
    if (l) {
      lim++;
      if (typeof l !== "object" || !("checked" in l))
        return [false, `record #${i+1}: limits invalid`];
    }
    const a = r.approval as Record<string, unknown> | undefined;
    if (a) {
      appr++;
      if (typeof a.id !== "string") return [false, `record #${i+1}: approval.id invalid`];
      if (!["pending","approved","denied"].includes(String(a.status)))
        return [false, `record #${i+1}: approval.status invalid`];
    }
  }
  if (!lim && !appr) return [true, "no limits/approval extensions"];
  return [true, `${lim} limits, ${appr} approval`];
}

function verifyAnchors(audit: LoadedLine[], anchors: LoadedLine[]): [boolean, string] {
  if (!anchors.length) return [false, "anchors file empty"];
  let prev = "ANCHOR_GENESIS";
  for (let i = 0; i < anchors.length; i++) {
    const { record: a, decimalPaths } = anchors[i];
    const body: Record<string, unknown> = {};
    for (const k of Object.keys(a)) {
      if (k !== "anchor_hash") body[k] = a[k];
    }
    if (body.prev_anchor !== prev) return [false, `anchor #${i+1}: broken chain`];
    if (hash(prev, body as Record<string, unknown>, decimalPaths) !== a.anchor_hash)
      return [false, `anchor #${i+1}: hash mismatch`];
    prev = a.anchor_hash as string;
  }
  const heads = audit.map(l => l.record.this_hash);
  for (let i = 0; i < anchors.length; i++) {
    const count = (anchors[i].record.count as number) || 0;
    if (count && heads[count-1] !== anchors[i].record.audit_head)
      return [false, `anchor #${i+1}: audit head mismatch`];
  }
  return [true, `verified ${anchors.length} anchor(s)`];
}

function check(auditPath: string, anchorsPath?: string) {
  const lines = load(auditPath);
  const records = lines.map(l => l.record);
  const passed: string[] = [], failed: string[] = [];
  if (!records.length) {
    failed.push("empty audit log");
    return { level: 0, passed, failed };
  }
  const schemaOk = records.every((r, i) => {
    const miss = REQUIRED.filter(f => !(f in r));
    if (miss.length) { failed.push(`?3 #${i+1} missing ${miss.join(",")}`); return false; }
    return true;
  });
  if (schemaOk) passed.push("?3 schema ok");
  const decOk = records.every(r => r.decision === "allow" || r.decision === "block");
  (decOk ? passed : failed).push(decOk ? "?2.1 decisions ok" : "?2.1 bad decision");
  const redOk = records.every(r => typeof r.redaction_hits === "object");
  (redOk ? passed : failed).push(redOk ? "?2.2 redaction ok" : "?2.2 redaction missing");
  const [cOk, cMsg] = verifyChain(lines);
  (cOk ? passed : failed).push("?2.6 " + cMsg);
  const [iOk, iMsg] = verifyIdentity(records);
  (iOk ? passed : failed).push("2.10 " + iMsg);
  const [laOk, laMsg] = verifyLimitsApproval(records);
  (laOk ? passed : failed).push("2.4/2.5 " + laMsg);
  const level1 = schemaOk && decOk && redOk && cOk && iOk && laOk;
  const safeOk = records.every(r => "safety" in r);
  (safeOk ? passed : failed).push(safeOk ? "?2.3 safety ok" : "?2.3 safety missing");
  const level2 = level1 && safeOk;
  let level3 = false;
  if (anchorsPath) {
    const [aOk, aMsg] = verifyAnchors(lines, load(anchorsPath));
    (aOk ? passed : failed).push("?2.7 " + aMsg);
    level3 = level2 && aOk;
  } else failed.push("?2.7 no anchors file");
  const level = level3 ? 3 : level2 ? 2 : level1 ? 1 : 0;
  return { spec: SPEC_VERSION, level, passed, failed };
}

function main() {
  const args = process.argv.slice(2);
  const audit = args.find(a => !a.startsWith("-"))!;
  const anchorsIdx = args.indexOf("--anchors");
  const anchors = anchorsIdx >= 0 ? args[anchorsIdx + 1] : undefined;
  const reqIdx = args.indexOf("--require");
  const require = reqIdx >= 0 ? parseInt(args[reqIdx + 1], 10) : undefined;
  const res = check(audit, anchors);
  console.log(`MCP-SP (TS): Level ${res.level}`);
  res.passed.forEach(m => console.log("  PASS", m));
  res.failed.forEach(m => console.log("  ---", m));
  if (require && res.level < require) process.exit(1);
}

main();
