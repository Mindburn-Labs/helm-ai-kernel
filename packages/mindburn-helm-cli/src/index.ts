// ─── HELM CLI v3 — Public API ────────────────────────────────────────────────
// Re-exports for programmatic use.

export {
    computeManifestRootHash,
    computeMerkleRoot,
    sha256Hex,
    sha256Raw,
    verifyEd25519,
    verifyAttestationSignature,
    canonicalJSON,
    PINNED_PUBLIC_KEYS,
} from "./crypto.js";

export { verifyBundle } from "./verify.js";

export {
    resolveLatestRelease,
    downloadBundle,
    getCachedBundle,
    ensureCacheDir,
    getCacheDir,
} from "./bundle.js";

export { renderResult, renderJSON, renderGateDetails, hyperlink, fileLink } from "./render.js";
export { renderHtmlReport } from "./report.js";

export { LEVELS, PROFILES, GATE_NAMES, PROFILES_VERSION, gatesForLevel, gateName } from "./gates.js";

export type {
    CLIOptions,
    ConformanceLevel,
    VerificationResult,
    StructureCheck,
    HashChainCheck,
    SignatureCheck,
    GateCheck,
    AttestationCheck,
    Attestation,
    IndexManifest,
    IndexEntry,
    ConformanceReport,
    GateResult,
} from "./types.js";
