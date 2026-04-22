// ─── HELM Interactive CLI Flow ───────────────────────────────────────────────
// @clack/prompts progressive disclosure.

import * as p from "@clack/prompts";
import { resolve } from "node:path";

import {
    downloadBundle,
    ensureCacheDir,
    resolveLatestRelease,
} from "./bundle.js";
import type { ConformanceLevel, VerificationResult } from "./types.js";
import { verifyBundle } from "./verify.js";
import { renderGateDetails, renderResult } from "./render.js";
import { renderHtmlReport } from "./report.js";

/**
 * Run the full interactive verification flow.
 * Returns exit code: 0 = pass, 1 = fail, 2 = error, 3 = no bundle.
 */
export async function runInteractive(options: {
    noCache?: boolean;
    cacheDir?: string;
}): Promise<number> {
    p.intro("HELM — Verifiable AI Governance");

    // ─── Step 1: Artifact Source ──────────────────────────────────────────

    const source = await p.select({
        message: "Artifact source",
        options: [
            {
                value: "latest" as const,
                label: "Latest OSS release",
                hint: "downloads from GitHub",
            },
            {
                value: "local" as const,
                label: "Local bundle path",
            },
        ],
    });

    if (p.isCancel(source)) {
        p.cancel("Cancelled.");
        return 2;
    }

    let bundlePath: string;

    if (source === "local") {
        const localPath = await p.text({
            message: "Bundle path",
            placeholder: "./artifacts/conformance",
            validate: (value: string | undefined) => {
                if (!value?.trim()) return "Path is required";
                return undefined;
            },
        });

        if (p.isCancel(localPath)) {
            p.cancel("Cancelled.");
            return 2;
        }

        bundlePath = resolve(localPath);
    } else {
        const spin = p.spinner();
        spin.start("Resolving latest release…");

        const release = await resolveLatestRelease();
        if (!release || !release.bundleUrl) {
            spin.stop("No release found");
            p.log.error("Could not resolve latest HELM release from GitHub.");
            p.log.info("Try using --bundle <path> with a local evidence bundle.");
            p.outro("Done");
            return 3;
        }

        spin.message(`Downloading ${release.tag}…`);
        ensureCacheDir(options.cacheDir);

        try {
            bundlePath = await downloadBundle(release.bundleUrl, {
                attestationUrl: release.attestationUrl,
                signatureUrl: release.signatureUrl,
                noCache: options.noCache,
                cacheDir: options.cacheDir,
                onProgress: (progress) => {
                    if (progress.phase === "downloading" && progress.totalBytes) {
                        const pct = Math.round(
                            (progress.bytesDownloaded / progress.totalBytes) * 100,
                        );
                        const mb = (progress.bytesDownloaded / 1_048_576).toFixed(1);
                        spin.message(`Downloading ${release.tag}… ${mb} MB (${pct}%)`);
                    } else if (progress.phase === "extracting") {
                        spin.message("Extracting bundle…");
                    } else if (progress.phase === "verifying") {
                        spin.message("Verifying attestation…");
                    }
                },
            });

            spin.stop(`Cached → ${bundlePath}`);
        } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            spin.stop(`Download failed: ${msg}`);
            p.outro("Done");
            return 2;
        }
    }

    // ─── Step 2: Conformance Level ───────────────────────────────────────

    const level = await p.select({
        message: "Conformance level",
        options: [
            {
                value: "L2" as ConformanceLevel,
                label: "L2 — Recommended",
                hint: "9 gates: budget, HITL, replay, tenant, envelope",
            },
            {
                value: "L1" as ConformanceLevel,
                label: "L1 — Minimal",
                hint: "3 gates: deterministic bytes, ProofGraph, EvidencePack",
            },
        ],
    });

    if (p.isCancel(level)) {
        p.cancel("Cancelled.");
        return 2;
    }

    // ─── Step 3: Verification ────────────────────────────────────────────

    const spin = p.spinner();
    spin.start("Verifying bundle…");

    let result: VerificationResult;
    try {
        result = await verifyBundle(bundlePath, level);
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        spin.stop(`Verification error: ${msg}`);
        p.outro("Done");
        return 2;
    }

    spin.stop(
        result.verdict === "PASS"
            ? `Verified — ${result.gates.passedGates}/${result.gates.totalGates} gates passed`
            : `Failed — ${result.gates.totalGates - result.gates.passedGates} gates failed`,
    );

    // ─── Step 4: Result Display ──────────────────────────────────────────

    renderResult(result, 1);

    // ─── Step 5: Drill Down ──────────────────────────────────────────────

    const next = await p.select({
        message: "What next?",
        options: [
            { value: "done" as const, label: "Done" },
            { value: "details" as const, label: "Show gate details" },
            { value: "report" as const, label: "Generate HTML report" },
        ],
    });

    if (!p.isCancel(next)) {
        if (next === "details") {
            renderGateDetails(result.gates.gateResults);
        } else if (next === "report") {
            const reportPath = await p.text({
                message: "Report output path",
                placeholder: "./helm-report.html",
                defaultValue: "./helm-report.html",
            });

            if (!p.isCancel(reportPath)) {
                const resolvedPath = resolve(reportPath);
                renderHtmlReport(result, resolvedPath);
                p.log.success(`Report written to ${resolvedPath}`);
            }
        }
    }

    p.outro(`Verified in ${result.timing_ms}ms`);

    return result.verdict === "PASS" ? 0 : 1;
}
