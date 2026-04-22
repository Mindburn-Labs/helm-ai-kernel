import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyBundle } from "../src/verify.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(__dirname, "..", "..", "..", "fixtures", "minimal");

describe("golden fixture verification", () => {
    it("verifies the minimal fixture with expected roots", async () => {
        const expected = JSON.parse(
            readFileSync(join(FIXTURE_DIR, "EXPECTED.json"), "utf-8"),
        );

        const result = await verifyBundle(FIXTURE_DIR, "L2");

        expect(result.schema_version).toBe("1");
        expect(result.verdict).toBe(expected.expected_verdict);
        expect(result.roots.manifest_root_hash).toBe(expected.bundle_root);
        expect(result.roots.merkle_root).toBe(expected.merkle_root);
        expect(result.structure.pass).toBe(true);
        expect(result.hash_chain.pass).toBe(true);
        expect(result.hash_chain.failedEntries).toEqual([]);
    });

    it("produces deterministic roots across repeated runs", async () => {
        const result1 = await verifyBundle(FIXTURE_DIR, "L2");
        const result2 = await verifyBundle(FIXTURE_DIR, "L2");

        expect(result1.roots.manifest_root_hash).toBe(result2.roots.manifest_root_hash);
        expect(result1.roots.merkle_root).toBe(result2.roots.merkle_root);
    });
});
