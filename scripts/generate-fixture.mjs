// Generate the minimal golden fixture for HELM OSS.
// Run: node scripts/generate-fixture.mjs
// Output: fixtures/minimal/ with deterministic 00_INDEX.json, 01_SCORE.json, and EXPECTED.json

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const FIXTURE_DIR = join(import.meta.dirname, "..", "fixtures", "minimal");

// ─── Helper ──────────────────────────────────────────────────────────────────

function sha256Hex(buf) {
    return createHash("sha256").update(buf).digest("hex");
}

function sha256Raw(buf) {
    return createHash("sha256").update(buf).digest();
}

function canonicalJSON(obj) {
    return JSON.stringify(sortKeys(obj));
}

function sortKeys(value) {
    if (value === null || typeof value !== "object") return value;
    if (Array.isArray(value)) return value.map(sortKeys);
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
        sorted[key] = sortKeys(value[key]);
    }
    return sorted;
}

// ─── 1. Create a minimal log file as evidence ────────────────────────────────

const logContent = `{"event":"verify","ts":"2026-02-21T00:00:00Z","status":"pass"}\n`;
const logPath = "06_LOGS/verify.jsonl";
writeFileSync(join(FIXTURE_DIR, logPath), logContent);
const logHash = sha256Hex(Buffer.from(logContent));

// ─── 2. Build score, index, and roots (two-pass for root embedding) ──────────

const gateResults = [
    { gate_id: "G0", status: "pass", pass: true, reasons: [], evidence_paths: [], metrics: { duration_ms: 1 } },
    { gate_id: "G1", status: "pass", pass: true, reasons: [], evidence_paths: [], metrics: { duration_ms: 1 } },
    { gate_id: "G2", status: "pass", pass: true, reasons: [], evidence_paths: [], metrics: { duration_ms: 1 } },
    { gate_id: "G2A", status: "pass", pass: true, reasons: [], evidence_paths: [], metrics: { duration_ms: 1 } },
    { gate_id: "G3A", status: "pass", pass: true, reasons: [], evidence_paths: [], metrics: { duration_ms: 1 } },
    { gate_id: "G5", status: "pass", pass: true, reasons: [], evidence_paths: [], metrics: { duration_ms: 1 } },
    { gate_id: "G8", status: "pass", pass: true, reasons: [], evidence_paths: [], metrics: { duration_ms: 1 } },
    { gate_id: "GX_ENVELOPE", status: "pass", pass: true, reasons: [], evidence_paths: [], metrics: { duration_ms: 1 } },
    { gate_id: "GX_TENANT", status: "pass", pass: true, reasons: [], evidence_paths: [], metrics: { duration_ms: 1 } },
];

// Pass 1: Write score without roots, build index, compute roots
const scoreDraft = canonicalJSON({
    run_id: "fixture-minimal-001", profile: "CORE",
    timestamp: "2026-02-21T00:00:00Z", pass: true,
    gate_results: gateResults, duration: 9,
    bundle_root: "", merkle_root: "",
});
writeFileSync(join(FIXTURE_DIR, "01_SCORE.json"), scoreDraft);

const indexDraft = {
    format_version: "3.0.0", run_id: "fixture-minimal-001", profile: "CORE",
    created_at: "2026-02-21T00:00:00Z", topo_order_rule: "creation_timestamp",
    entries: [
        { path: "01_SCORE.json", sha256: sha256Hex(Buffer.from(scoreDraft)), size_bytes: Buffer.byteLength(scoreDraft), kind: "helm:report" },
        { path: logPath, sha256: logHash, size_bytes: Buffer.byteLength(logContent), kind: "helm:log" },
    ],
};
const indexDraftJson = canonicalJSON(indexDraft);
const bundleRootDraft = sha256Hex(Buffer.from(indexDraftJson));

// Compute Merkle root
const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function computeMerkle(entries) {
    const sorted = [...entries].sort((a, b) => a.path.localeCompare(b.path));
    let nodes = sorted.map(e => sha256Raw(Buffer.concat([LEAF_PREFIX, Buffer.from(e.sha256, "hex")])));
    while (nodes.length > 1) {
        const next = [];
        for (let i = 0; i < nodes.length; i += 2) {
            const left = nodes[i];
            const right = i + 1 < nodes.length ? nodes[i + 1] : nodes[i];
            next.push(sha256Raw(Buffer.concat([NODE_PREFIX, left, right])));
        }
        nodes = next;
    }
    return nodes[0].toString("hex");
}

const merkleRootDraft = computeMerkle(indexDraft.entries);

// Pass 2: Rewrite score WITH roots, then rewrite index with final score hash
const scoreFinal = canonicalJSON({
    run_id: "fixture-minimal-001", profile: "CORE",
    timestamp: "2026-02-21T00:00:00Z", pass: true,
    gate_results: gateResults, duration: 9,
    bundle_root: bundleRootDraft, merkle_root: merkleRootDraft,
});
writeFileSync(join(FIXTURE_DIR, "01_SCORE.json"), scoreFinal);

const indexFinal = {
    format_version: "3.0.0", run_id: "fixture-minimal-001", profile: "CORE",
    created_at: "2026-02-21T00:00:00Z", topo_order_rule: "creation_timestamp",
    entries: [
        { path: "01_SCORE.json", sha256: sha256Hex(Buffer.from(scoreFinal)), size_bytes: Buffer.byteLength(scoreFinal), kind: "helm:report" },
        { path: logPath, sha256: logHash, size_bytes: Buffer.byteLength(logContent), kind: "helm:log" },
    ],
};
const indexJson = canonicalJSON(indexFinal);
writeFileSync(join(FIXTURE_DIR, "00_INDEX.json"), indexJson);

// Final roots (from the index that references the score-with-roots)
const bundleRoot = sha256Hex(Buffer.from(indexJson));
const merkleRoot = computeMerkle(indexFinal.entries);

// ─── 3. Write EXPECTED.json ──────────────────────────────────────────────────

const expected = {
    bundle_root: bundleRoot,
    merkle_root: merkleRoot,
    expected_verdict: "PASS",
    expected_gates: gateResults.map(g => g.gate_id),
    description: "Expected verification roots and outcomes for the minimal golden fixture.",
};

writeFileSync(
    join(FIXTURE_DIR, "EXPECTED.json"),
    JSON.stringify(expected, null, 2) + "\n",
);

// Remove old expected-roots.json if present
import { unlinkSync } from "node:fs";
try { unlinkSync(join(FIXTURE_DIR, "expected-roots.json")); } catch { }

console.log("Golden fixture generated:");
console.log(`  bundle_root: ${bundleRoot}`);
console.log(`  merkle_root: ${merkleRoot}`);
console.log(`  entries:     ${indexFinal.entries.length}`);
console.log(`  path:        fixtures/minimal/`);

