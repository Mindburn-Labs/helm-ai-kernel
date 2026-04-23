// ─── HELM CLI v3 Terminal Rendering ──────────────────────────────────────────
// ANSI output with OSC 8 hyperlinks, dual-channel (stderr human / stdout JSON).

import { GATE_NAMES } from "./gates.js";
import type { GateResult, VerificationResult } from "./types.js";

// ─── ANSI Helpers ────────────────────────────────────────────────────────────

const isColorSupported =
    process.env.FORCE_COLOR !== "0" &&
    (process.env.FORCE_COLOR !== undefined || (process.stderr.isTTY ?? false));

const c = {
    reset: isColorSupported ? "\x1b[0m" : "",
    bold: isColorSupported ? "\x1b[1m" : "",
    dim: isColorSupported ? "\x1b[2m" : "",
    green: isColorSupported ? "\x1b[32m" : "",
    red: isColorSupported ? "\x1b[31m" : "",
    yellow: isColorSupported ? "\x1b[33m" : "",
    cyan: isColorSupported ? "\x1b[36m" : "",
    gray: isColorSupported ? "\x1b[90m" : "",
};

// ─── OSC 8 Hyperlinks ───────────────────────────────────────────────────────

const isHyperlinkSupported =
    isColorSupported &&
    (process.env.TERM_PROGRAM === "iTerm.app" ||
        process.env.TERM_PROGRAM === "WezTerm" ||
        process.env.TERM_PROGRAM === "vscode" ||
        process.env.WT_SESSION !== undefined ||
        process.env.TERM?.includes("xterm"));

export function hyperlink(text: string, url: string): string {
    if (!isHyperlinkSupported) return text;
    return `\x1b]8;;${url}\x1b\\${text}\x1b]8;;\x1b\\`;
}

export function fileLink(path: string): string {
    return hyperlink(path, `file://${path}`);
}

// ─── Result Rendering ────────────────────────────────────────────────────────

/**
 * Render verification result to stderr at the specified depth.
 *
 * Depth 0: badge only (PASS/FAIL + short hash)
 * Depth 1: summary (structure, hash chain, signature, gates, roots)
 * Depth 2: per-gate detail
 * Depth 3: full tree with leaf counts
 */
export function renderResult(result: VerificationResult, depth: number): void {
    const w = (s: string) => process.stderr.write(`${s}\n`);

    const badge = result.verdict === "PASS"
        ? `${c.green}${c.bold}✅ PASS${c.reset}`
        : `${c.red}${c.bold}❌ FAIL${c.reset}`;

    if (depth === 0) {
        w(`${badge}  ${c.dim}${result.roots.manifest_root_hash.substring(0, 16)}…${c.reset}`);
        return;
    }

    // Depth 1+: Summary
    w("");
    w(`${c.bold}  Verification${c.reset}`);
    w("");

    const checks: Array<{ pass: boolean; label: string; detail: string }> = [
        {
            pass: result.structure.pass,
            label: "Structure",
            detail: result.structure.pass
                ? `${result.structure.dirCount} dirs, 00_INDEX.json, 01_SCORE.json`
                : `missing: ${result.structure.missingDirs.join(", ")}`,
        },
        {
            pass: result.hash_chain.pass,
            label: "Hash chain",
            detail: result.hash_chain.pass
                ? `${result.hash_chain.verifiedEntries}/${result.hash_chain.totalEntries} entries verified`
                : `${result.hash_chain.failedEntries.length} entries failed`,
        },
        {
            pass: result.signature.pass,
            label: "Signature",
            detail: result.signature.pass
                ? result.signature.signerID
                    ? `signed by ${result.signature.signerID}`
                    : `conformance_report.sig valid`
                : result.signature.reason ?? "failed",
        },
        {
            pass: result.gates.pass,
            label: "Gates",
            detail: `${result.gates.passedGates}/${result.gates.totalGates} passed (${result.gates.level})`,
        },
        {
            pass: result.attestation.pass,
            label: "Attestation",
            detail: result.attestation.verified
                ? "Ed25519 verified"
                : result.attestation.reason ?? "not checked",
        },
    ];

    for (const check of checks) {
        const icon = check.pass ? `${c.green}✓${c.reset}` : `${c.red}✗${c.reset}`;
        w(`  ${icon} ${c.bold}${check.label.padEnd(14)}${c.reset}${c.dim}${check.detail}${c.reset}`);
    }

    w("");
    w(`  ${c.bold}Status${c.reset}        ${badge}`);
    w(`  ${c.bold}Manifest${c.reset}      ${c.cyan}${result.roots.manifest_root_hash}${c.reset}`);
    w(`  ${c.bold}Merkle root${c.reset}   ${c.cyan}${result.roots.merkle_root}${c.reset}`);
    w(`  ${c.bold}Evidence${c.reset}      ${fileLink(result.evidence)}`);
    w(`  ${c.bold}Duration${c.reset}      ${c.dim}${result.timing_ms}ms${c.reset}`);
    w("");

    // Depth 2+: Gate details
    if (depth >= 2) {
        renderGateDetails(result.gates.gateResults);
    }

    // Depth 3: Evidence tree summary + attestation details
    if (depth >= 3) {
        w(`  ${c.bold}Evidence Tree${c.reset}`);
        w(`  ${c.dim}Total entries:   ${result.hash_chain.totalEntries} leaves${c.reset}`);
        w(`  ${c.dim}Verified:        ${result.hash_chain.verifiedEntries}${c.reset}`);
        w(`  ${c.dim}Failed:          ${result.hash_chain.failedEntries.length}${c.reset}`);
        w("");

        // Attestation details
        if (result.attestation.attestation) {
            const att = result.attestation.attestation;
            w(`  ${c.bold}Attestation${c.reset}`);
            w(`  ${c.dim}Key ID:          ${att.keys_key_id}${c.reset}`);
            w(`  ${c.dim}Profiles hash:   ${att.profiles_manifest_sha256}${c.reset}`);
            if (att.producer) {
                w(`  ${c.dim}Producer:        ${att.producer.name} v${att.producer.version}${att.producer.commit ? ` (${att.producer.commit.substring(0, 8)})` : ""}${c.reset}`);
            }
            w("");
        }
    }
}

/**
 * Render per-gate breakdown to stderr.
 */
export function renderGateDetails(gates: GateResult[]): void {
    const w = (s: string) => process.stderr.write(`${s}\n`);

    w(`  ${c.bold}Gate Details${c.reset}`);
    w(`  ${c.dim}${"─".repeat(60)}${c.reset}`);

    for (const gate of gates) {
        const passing = gate.status ? (gate.status === "pass" || gate.status === "skip" || gate.status === "na") : gate.pass;
        const icon = passing ? `${c.green}✓${c.reset}` : `${c.red}✗${c.reset}`;
        const name = GATE_NAMES[gate.gate_id] ?? gate.gate_id;
        const statusTag = gate.status ? ` ${c.dim}[${gate.status}]${c.reset}` : "";
        const dur = `${c.dim}${gate.metrics.duration_ms}ms${c.reset}`;

        w(`  ${icon} ${c.bold}${gate.gate_id.padEnd(14)}${c.reset} ${name.padEnd(28)} ${dur}${statusTag}`);

        if (!passing && gate.reasons.length > 0) {
            for (const reason of gate.reasons) {
                w(`    ${c.red}└ ${reason}${c.reset}`);
            }
        }
    }
    w("");
}

/**
 * Write verification result as JSON to stdout (CI mode).
 */
export function renderJSON(result: VerificationResult): void {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
