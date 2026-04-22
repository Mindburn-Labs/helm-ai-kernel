#!/usr/bin/env node
// ─── HELM CLI v3 Entrypoint ──────────────────────────────────────────────────
// npx @mindburn/helm — one command, progressive disclosure, cryptographic proof.
//
// Usage:
//   npx @mindburn/helm                              # Interactive flow
//   npx @mindburn/helm --ci --bundle ./evidence      # CI mode (JSON stdout)
//   npx @mindburn/helm --bundle ./ev --level L2      # Non-interactive
//   npx @mindburn/helm --report ./evidence.html      # HTML evidence report

import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { CLIOptions, ConformanceLevel } from "./types.js";
import { runInteractive } from "./interactive.js";
import { verifyBundle } from "./verify.js";
import { renderHtmlReport } from "./report.js";
import { renderJSON, renderResult } from "./render.js";

// ─── Version ─────────────────────────────────────────────────────────────────

function getVersion(): string {
    try {
        const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
        const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as { version: string };
        return pkg.version;
    } catch {
        return "3.0.0";
    }
}

// ─── Help ────────────────────────────────────────────────────────────────────

const HELP = `
  ${"\x1b[1m"}HELM${"\x1b[0m"} — Verifiable AI Governance

  ${"\x1b[2m"}Usage:${"\x1b[0m"}
    npx @mindburn/helm                     Interactive verification flow
    npx @mindburn/helm --ci --bundle PATH  CI mode (JSON stdout, exit code)

  ${"\x1b[2m"}Options:${"\x1b[0m"}
    --bundle PATH    Path to local evidence bundle directory
    --level L1|L2    Conformance level (default: L2)
    --ci             Non-interactive mode, JSON on stdout
    --json           Alias for --ci
    --depth 0-3      Output verbosity (default: 1)
    --report PATH    Generate single-file HTML evidence report
    --allow-unsigned Allow unsigned local bundles (default: false)
    --no-cache       Skip cache for downloads
    --cache-dir DIR  Custom cache directory (default: ~/.helm/cache)
    --help           Show this help
    --version        Show version

  ${"\x1b[2m"}Exit codes:${"\x1b[0m"}
    0  All checks pass
    1  One or more checks failed
    2  Runtime error
    3  No bundle found

  ${"\x1b[2m"}Examples:${"\x1b[0m"}
    npx @mindburn/helm
    npx @mindburn/helm --bundle ./artifacts/conformance --level L2
    npx @mindburn/helm --ci --bundle ./evidence 2>/dev/null | jq .verdict
    npx @mindburn/helm --bundle ./evidence --report ./report.html
    npx @mindburn/helm --bundle ./evidence --depth 3
`;

// ─── Parse ───────────────────────────────────────────────────────────────────

function parseOptions(): CLIOptions {
    const { values } = parseArgs({
        options: {
            bundle: { type: "string" },
            level: { type: "string" },
            ci: { type: "boolean", default: false },
            json: { type: "boolean", default: false },
            depth: { type: "string", default: "1" },
            report: { type: "string" },
            "allow-unsigned": { type: "boolean", default: false },
            "no-cache": { type: "boolean", default: false },
            "cache-dir": { type: "string" },
            help: { type: "boolean", short: "h", default: false },
            version: { type: "boolean", short: "v", default: false },
        },
        strict: true,
        allowPositionals: false,
    });

    const level = values.level as ConformanceLevel | undefined;
    if (level && level !== "L1" && level !== "L2") {
        process.stderr.write(`Error: --level must be L1 or L2, got "${level}"\n`);
        process.exit(2);
    }

    const depth = Number.parseInt(values.depth ?? "1", 10);
    if (Number.isNaN(depth) || depth < 0 || depth > 3) {
        process.stderr.write("Error: --depth must be 0-3\n");
        process.exit(2);
    }

    return {
        bundle: values.bundle,
        level,
        ci: values.ci ?? values.json ?? false,
        json: values.json ?? false,
        depth,
        report: values.report,
        allowUnsigned: values["allow-unsigned"] ?? false,
        noCache: values["no-cache"] ?? false,
        cacheDir: values["cache-dir"],
        help: values.help ?? false,
        version: values.version ?? false,
    };
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<never> {
    const opts = parseOptions();

    if (opts.help) {
        process.stderr.write(HELP);
        process.exit(0);
    }

    if (opts.version) {
        process.stderr.write(`@mindburn/helm v${getVersion()}\n`);
        process.exit(0);
    }

    // Non-interactive mode
    if (opts.ci || opts.json || opts.bundle) {
        const exitCode = await runNonInteractive(opts);
        process.exit(exitCode);
    }

    // Interactive mode
    const exitCode = await runInteractive({
        noCache: opts.noCache,
        cacheDir: opts.cacheDir,
    });
    process.exit(exitCode);
}

// ─── Non-Interactive ─────────────────────────────────────────────────────────

async function runNonInteractive(opts: CLIOptions): Promise<number> {
    if (!opts.bundle) {
        process.stderr.write("Error: --bundle is required in CI mode\n");
        return 2;
    }

    const bundlePath = resolve(opts.bundle);
    const level: ConformanceLevel = opts.level ?? "L2";

    if (!opts.ci) {
        process.stderr.write(`Verifying ${bundlePath} at ${level}…\n`);
    }

    let result;
    try {
        result = await verifyBundle(bundlePath, level);
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(`Error: ${msg}\n`);
        return 2;
    }

    // HTML report
    if (opts.report) {
        const reportPath = resolve(opts.report);
        renderHtmlReport(result, reportPath);
        process.stderr.write(`Report written to ${reportPath}\n`);
    }

    // Output
    if (opts.ci || opts.json) {
        renderResult(result, 0); // badge on stderr
        renderJSON(result);      // JSON on stdout
    } else {
        renderResult(result, opts.depth);
    }

    return result.verdict === "PASS" ? 0 : 1;
}

// ─── Entry ───────────────────────────────────────────────────────────────────

main().catch((err: unknown) => {
    process.stderr.write(`Fatal: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(2);
});
