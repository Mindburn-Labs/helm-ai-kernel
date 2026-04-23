// ─── HELM CLI v3 Types ───────────────────────────────────────────────────────
// Stable JSON schema for all CLI inputs and outputs.
// Schema version: 1

/** Conformance level shortcut. */
export type ConformanceLevel = "L1" | "L2";

/** CLI invocation options parsed from argv. */
export interface CLIOptions {
    bundle?: string;
    level?: ConformanceLevel;
    ci: boolean;
    json: boolean;
    depth: number;
    report?: string;
    noCache: boolean;
    cacheDir?: string;
    allowUnsigned: boolean;
    help: boolean;
    version: boolean;
}

// ─── Bundle Schema ───────────────────────────────────────────────────────────

/**
 * Evidence Pack entry kind vocabulary (open — extend as needed).
 * Recommended values use a namespace prefix:
 *   helm:log, helm:proofgraph, helm:snapshot, helm:report,
 *   helm:manifest, helm:schema, helm:tape, helm:other
 */
export type EntryKind = string;

/** Index entry in 00_INDEX.json. */
export interface IndexEntry {
    path: string;
    sha256: string;
    size_bytes: number;
    kind: EntryKind;
    meta?: Record<string, unknown>;
}

/** Index manifest (00_INDEX.json). */
export interface IndexManifest {
    format_version: string;
    run_id: string;
    profile: string;
    created_at: string;
    topo_order_rule: string;
    entries: IndexEntry[];
}

// ─── Gate Results ────────────────────────────────────────────────────────────

/** Gate evaluation status. */
export type GateStatus = "pass" | "fail" | "skip" | "na" | "error";

/** Gate result from 01_SCORE.json. */
export interface GateResult {
    gate_id: string;
    status: GateStatus;
    /** @deprecated Use `status` instead. Kept for backward compat. */
    pass: boolean;
    reasons: string[];
    evidence_paths: string[];
    metrics: {
        duration_ms: number;
        counts?: Record<string, number>;
    };
    details?: Record<string, unknown>;
}

/** Conformance report from 01_SCORE.json. */
export interface ConformanceReport {
    run_id: string;
    profile: string;
    timestamp: string;
    pass: boolean;
    gate_results: GateResult[];
    duration: number | string;
    bundle_root?: string;
    merkle_root?: string;
    metadata?: Record<string, unknown>;
}

// ─── Attestation Schema ──────────────────────────────────────────────────────

/** Producer metadata embedded in attestation. */
export interface Producer {
    name: string;
    version: string;
    commit?: string;
}

/** v3 release attestation — signed with Ed25519. */
export interface Attestation {
    format: "helm-attestation-v3";
    release_tag: string;
    asset_name: string;
    asset_sha256: string;
    manifest_root_hash: string;
    merkle_root: string;
    created_at: string;
    profiles_manifest_sha256: string;
    keys_key_id: string;
    producer: Producer;
}

// ─── Verification Result Types ───────────────────────────────────────────────

export interface StructureCheck {
    pass: boolean;
    dirCount: number;
    hasIndex: boolean;
    hasScore: boolean;
    missingDirs: string[];
    extraEntries: string[];
}

export interface HashChainCheck {
    pass: boolean;
    totalEntries: number;
    verifiedEntries: number;
    failedEntries: Array<{ path: string; expected: string; actual: string }>;
}

export interface SignatureCheck {
    pass: boolean;
    signerID?: string;
    signedAt?: string;
    reason?: string;
}

export interface GateCheck {
    pass: boolean;
    level: ConformanceLevel;
    totalGates: number;
    passedGates: number;
    failedGates: GateResult[];
    gateResults: GateResult[];
}

export interface AttestationCheck {
    pass: boolean;
    verified: boolean;
    reason?: string;
    attestation?: Attestation;
}

// ─── CI Output Schema (v1) ──────────────────────────────────────────────────

/** Structured data payload for integrators. */
export interface CIOutputData {
    tool: { name: string; version: string };
    artifact: {
        source: "latest_release" | "local_bundle";
        release_tag?: string;
        asset_name?: string;
        asset_sha256?: string;
        bundle_path?: string;
        cache_path?: string;
    };
    profile: {
        level: string;
        gates_requested: string[];
        gates_run: string[];
    };
    timing_ms: {
        total: number;
        download?: number;
        verify?: number;
    };
    gates: Array<{
        id: string;
        status: GateStatus;
        duration_ms: number;
        reason_code?: string;
        detail_path?: string;
    }>;
    attestation?: {
        keys_key_id?: string;
        profiles_manifest_sha256?: string;
        producer?: Producer;
    };
    links?: {
        release_url?: string;
        report_url?: string;
    };
}

/**
 * Complete CI output — stable JSON schema (v1).
 *
 * Top-level: flat convenience fields for `jq .verdict` ergonomics.
 * data: structured payload for integrators and website.
 */
export interface CIOutput {
    schema_version: "1";
    // ── Flat convenience (jq-friendly) ──
    verdict: "PASS" | "FAIL" | "ERROR" | "NOT_FOUND";
    exit_code: 0 | 1 | 2 | 3;
    bundle_root: string;
    merkle_root: string;
    release_tag?: string;
    report_path?: string;
    // ── Structured data ──
    data: CIOutputData;
}

/** Internal verification result (used before CI output transform). */
export interface VerificationResult {
    schema_version: "1";
    tool: string;
    artifact: string;
    verdict: "PASS" | "FAIL";
    profile: string;
    timing_ms: number;
    roots: {
        manifest_root_hash: string;
        merkle_root: string;
    };
    structure: StructureCheck;
    hash_chain: HashChainCheck;
    signature: SignatureCheck;
    gates: GateCheck;
    attestation: AttestationCheck;
    evidence: string;
}
