// ─── HELM v3 Verification Tests ──────────────────────────────────────────────
// Golden tests: synthetic §3.1 bundles, hash chain, tamper detection, gates.

import { createHash } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, it, expect, beforeAll, afterAll } from "vitest";

import { verifyBundle } from "../src/verify.js";
import { LEVELS } from "../src/gates.js";
import type {
    ConformanceReport,
    IndexManifest,
} from "../src/types.js";

// ─── Fixture Builder ─────────────────────────────────────────────────────────

const MANDATORY_DIRS = [
    "02_PROOFGRAPH", "03_TELEMETRY", "04_EXPORTS", "05_DIFFS",
    "06_LOGS", "07_ATTESTATIONS", "08_TAPES", "09_SCHEMAS",
    "12_REPORTS",
];

function sha256(data: string | Buffer): string {
    return createHash("sha256").update(data).digest("hex");
}

interface ReportSig {
    index_hash: string;
    score_hash: string;
    policy_hash: string;
    schema_bundle_hash: string;
    signature: string;
    signed_at: string;
    signer_id: string;
}

function createBundle(root: string, opts?: { failGates?: string[] }): void {
    mkdirSync(root, { recursive: true });
    for (const d of MANDATORY_DIRS) mkdirSync(join(root, d), { recursive: true });

    // Evidence artifact
    const evidence = JSON.stringify({ type: "proofgraph", entries: [] });
    writeFileSync(join(root, "02_PROOFGRAPH/graph.json"), evidence);

    // Score with configurable gate failures
    const failGates = new Set(opts?.failGates ?? []);
    const gateResults = LEVELS.L2.gates.map((gateId) => ({
        gate_id: gateId,
        status: (failGates.has(gateId) ? "fail" : "pass") as "pass" | "fail",
        pass: !failGates.has(gateId),
        reasons: failGates.has(gateId) ? ["TEST_FAILURE"] : [],
        evidence_paths: [],
        metrics: { duration_ms: Math.floor(Math.random() * 50) + 5 },
    }));

    const score: ConformanceReport = {
        run_id: "fixture-run-001",
        profile: "CORE",
        timestamp: "2026-02-21T12:00:00Z",
        pass: failGates.size === 0,
        gate_results: gateResults,
        duration: "1.0s",
    };
    const scoreJson = JSON.stringify(score, null, 2);
    writeFileSync(join(root, "01_SCORE.json"), scoreJson);

    // Index
    const index: IndexManifest = {
        format_version: "3.0.0",
        run_id: "fixture-run-001",
        profile: "CORE",
        created_at: "2026-02-21T12:00:00Z",
        topo_order_rule: "deterministic",
        entries: [
            {
                path: "01_SCORE.json",
                sha256: sha256(scoreJson),
                size_bytes: Buffer.byteLength(scoreJson),
                kind: "helm:report",
            },
            {
                path: "02_PROOFGRAPH/graph.json",
                sha256: sha256(evidence),
                size_bytes: Buffer.byteLength(evidence),
                kind: "helm:report",
            },
        ],
    };
    const indexJson = JSON.stringify(index, null, 2);
    writeFileSync(join(root, "00_INDEX.json"), indexJson);

    // Signature
    const ih = sha256(indexJson);
    const sh = sha256(scoreJson);
    const ph = sha256("policy");
    const sbh = sha256("schema");
    const payload = JSON.stringify({ index_hash: ih, score_hash: sh, policy_hash: ph, schema_bundle_hash: sbh });
    const sig: ReportSig = {
        index_hash: ih, score_hash: sh, policy_hash: ph, schema_bundle_hash: sbh,
        signature: sha256(payload),
        signed_at: "2026-02-21T12:00:00Z",
        signer_id: "test-fixture",
    };
    writeFileSync(join(root, "07_ATTESTATIONS/conformance_report.sig"), JSON.stringify(sig, null, 2));
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("verifyBundle", () => {
    const root = join(tmpdir(), `helm-v3-test-${Date.now()}`);
    const valid = join(root, "valid");
    const broken = join(root, "broken");
    const failing = join(root, "failing");

    beforeAll(() => {
        createBundle(valid);
        createBundle(failing, { failGates: ["G0", "G1"] });

        // Broken bundle — missing dirs, minimal index
        mkdirSync(broken, { recursive: true });
        writeFileSync(join(broken, "00_INDEX.json"), JSON.stringify({ entries: [] }));
    });

    afterAll(() => {
        rmSync(root, { recursive: true, force: true });
    });

    // ─── Structure ──────────────────────────────────────

    it("passes structure on valid bundle", async () => {
        const r = await verifyBundle(valid, "L2");
        expect(r.structure.pass).toBe(true);
        expect(r.structure.dirCount).toBe(MANDATORY_DIRS.length);
        expect(r.structure.missingDirs).toHaveLength(0);
    });

    it("fails structure on broken bundle", async () => {
        const r = await verifyBundle(broken, "L1");
        expect(r.structure.pass).toBe(false);
        expect(r.structure.missingDirs.length).toBeGreaterThan(0);
    });

    // ─── Hash Chain ─────────────────────────────────────

    it("passes hash chain on valid bundle", async () => {
        const r = await verifyBundle(valid, "L2");
        expect(r.hash_chain.pass).toBe(true);
        expect(r.hash_chain.verifiedEntries).toBe(r.hash_chain.totalEntries);
    });

    it("detects tampered file", async () => {
        const tampered = join(root, "tampered");
        createBundle(tampered);
        writeFileSync(join(tampered, "02_PROOFGRAPH/graph.json"), "TAMPERED");

        const r = await verifyBundle(tampered, "L2");
        expect(r.hash_chain.pass).toBe(false);
        expect(r.hash_chain.failedEntries.length).toBeGreaterThan(0);

        rmSync(tampered, { recursive: true, force: true });
    });

    // ─── Roots ──────────────────────────────────────────

    it("computes both roots", async () => {
        const r = await verifyBundle(valid, "L2");
        expect(r.roots.manifest_root_hash).toHaveLength(64);
        expect(r.roots.merkle_root).toHaveLength(64);
        expect(r.roots.manifest_root_hash).not.toBe(r.roots.merkle_root);
    });

    // ─── Signature ──────────────────────────────────────

    it("passes signature on valid bundle", async () => {
        const r = await verifyBundle(valid, "L2");
        expect(r.signature.pass).toBe(true);
        expect(r.signature.signerID).toBe("test-fixture");
    });

    // ─── Gates ──────────────────────────────────────────

    it("passes L2 gates on valid bundle", async () => {
        const r = await verifyBundle(valid, "L2");
        expect(r.gates.pass).toBe(true);
        expect(r.gates.passedGates).toBe(LEVELS.L2.gates.length);
    });

    it("passes L1 gates on valid bundle", async () => {
        const r = await verifyBundle(valid, "L1");
        expect(r.gates.pass).toBe(true);
        expect(r.gates.passedGates).toBe(LEVELS.L1.gates.length);
    });

    it("detects gate failures", async () => {
        const r = await verifyBundle(failing, "L2");
        expect(r.gates.pass).toBe(false);
        expect(r.gates.failedGates.length).toBe(2);
    });

    // ─── Full Result ────────────────────────────────────

    it("full pass on valid bundle", async () => {
        const r = await verifyBundle(valid, "L2");
        expect(r.verdict).toBe("PASS");
        expect(r.tool).toBe("@mindburn/helm");
        expect(r.timing_ms).toBeGreaterThanOrEqual(0);
    });

    it("full fail on broken bundle", async () => {
        const r = await verifyBundle(broken, "L1");
        expect(r.verdict).toBe("FAIL");
    });

    // ─── JSON Schema ────────────────────────────────────

    it("output matches stable schema", async () => {
        const r = await verifyBundle(valid, "L2");
        // Required top-level fields
        expect(r).toHaveProperty("schema_version", "1");
        expect(r).toHaveProperty("tool");
        expect(r).toHaveProperty("artifact");
        expect(r).toHaveProperty("verdict");
        expect(r).toHaveProperty("profile");
        expect(r).toHaveProperty("timing_ms");
        expect(r).toHaveProperty("roots.manifest_root_hash");
        expect(r).toHaveProperty("roots.merkle_root");
        expect(r).toHaveProperty("structure");
        expect(r).toHaveProperty("hash_chain");
        expect(r).toHaveProperty("signature");
        expect(r).toHaveProperty("gates");
        expect(r).toHaveProperty("attestation");
        expect(r).toHaveProperty("evidence");
    });
});
