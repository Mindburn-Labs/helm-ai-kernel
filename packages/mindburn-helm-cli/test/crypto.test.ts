// ─── HELM v3 Crypto Tests ────────────────────────────────────────────────────
// Merkle tree, manifest root hash, Ed25519, canonical JSON.

import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";

import {
    computeManifestRootHash,
    computeMerkleRoot,
    sha256Hex,
    sha256Raw,
    canonicalJSON,
} from "../src/crypto.js";

// ─── Known Test Vectors ──────────────────────────────────────────────────────

function sha256(data: string): string {
    return createHash("sha256").update(data).digest("hex");
}

describe("computeManifestRootHash", () => {
    it("computes deterministic hash of buffer", () => {
        const data = Buffer.from('{"run_id":"test","entries":[]}');
        const h1 = computeManifestRootHash(data);
        const h2 = computeManifestRootHash(data);
        expect(h1).toBe(h2);
        expect(h1).toHaveLength(64);
    });

    it("different content produces different hash", () => {
        const h1 = computeManifestRootHash(Buffer.from("a"));
        const h2 = computeManifestRootHash(Buffer.from("b"));
        expect(h1).not.toBe(h2);
    });
});

describe("computeMerkleRoot", () => {
    it("handles empty entries", () => {
        const root = computeMerkleRoot([]);
        expect(root).toHaveLength(64);
    });

    it("single leaf produces deterministic root", () => {
        const hash = sha256("file-content");
        const root = computeMerkleRoot([{ path: "file.txt", sha256: hash }]);
        expect(root).toHaveLength(64);

        // Reproduce manually: single leaf → root = sha256(0x00 || hash_bytes)
        const LEAF_PREFIX = Buffer.from([0x00]);
        const hashBytes = Buffer.from(hash, "hex");
        const expectedRoot = sha256Raw(Buffer.concat([LEAF_PREFIX, hashBytes]));
        expect(root).toBe(expectedRoot.toString("hex"));
    });

    it("two leaves produce correct root", () => {
        const hashA = sha256("content-a");
        const hashB = sha256("content-b");
        const root = computeMerkleRoot([
            { path: "a.json", sha256: hashA },
            { path: "b.json", sha256: hashB },
        ]);
        expect(root).toHaveLength(64);

        // Manual: sorted by path → a.json, b.json
        const LEAF_PREFIX = Buffer.from([0x00]);
        const NODE_PREFIX = Buffer.from([0x01]);
        const leafA = sha256Raw(Buffer.concat([LEAF_PREFIX, Buffer.from(hashA, "hex")]));
        const leafB = sha256Raw(Buffer.concat([LEAF_PREFIX, Buffer.from(hashB, "hex")]));
        const expectedRoot = sha256Raw(Buffer.concat([NODE_PREFIX, leafA, leafB]));
        expect(root).toBe(expectedRoot.toString("hex"));
    });

    it("three leaves — odd leaf duplicated", () => {
        const entries = [
            { path: "c.json", sha256: sha256("c") },
            { path: "a.json", sha256: sha256("a") },
            { path: "b.json", sha256: sha256("b") },
        ];
        const root = computeMerkleRoot(entries);
        expect(root).toHaveLength(64);

        // Sorted: a, b, c
        const LEAF_PREFIX = Buffer.from([0x00]);
        const NODE_PREFIX = Buffer.from([0x01]);
        const leafA = sha256Raw(Buffer.concat([LEAF_PREFIX, Buffer.from(sha256("a"), "hex")]));
        const leafB = sha256Raw(Buffer.concat([LEAF_PREFIX, Buffer.from(sha256("b"), "hex")]));
        const leafC = sha256Raw(Buffer.concat([LEAF_PREFIX, Buffer.from(sha256("c"), "hex")]));

        // Level 1: pair(a,b), pair(c,c) — odd leaf duplicated
        const nodeAB = sha256Raw(Buffer.concat([NODE_PREFIX, leafA, leafB]));
        const nodeCC = sha256Raw(Buffer.concat([NODE_PREFIX, leafC, leafC]));

        // Level 2: pair(AB, CC)
        const expectedRoot = sha256Raw(Buffer.concat([NODE_PREFIX, nodeAB, nodeCC]));
        expect(root).toBe(expectedRoot.toString("hex"));
    });

    it("sorting is by path ascending", () => {
        const hash = sha256("x");
        // Same entries, different input order — same root
        const root1 = computeMerkleRoot([
            { path: "z.json", sha256: hash },
            { path: "a.json", sha256: hash },
        ]);
        const root2 = computeMerkleRoot([
            { path: "a.json", sha256: hash },
            { path: "z.json", sha256: hash },
        ]);
        expect(root1).toBe(root2);
    });
});

describe("canonicalJSON", () => {
    it("sorts keys", () => {
        const result = canonicalJSON({ b: 2, a: 1 });
        expect(result).toBe('{"a":1,"b":2}');
    });

    it("handles nested objects (top-level sort only)", () => {
        const result = canonicalJSON({ z: { inner: 1 }, a: "first" });
        expect(result).toBe('{"a":"first","z":{"inner":1}}');
    });
});
