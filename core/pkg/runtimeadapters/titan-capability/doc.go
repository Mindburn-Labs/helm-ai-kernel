// Package titancapability implements HELM runtime adapters for Titan-specific
// capability classes that gate the AI-native hedge fund's lifecycle actions.
//
// Every Titan capability call (model deploy, factor promote, data-source
// activate, feature read, market-data stream subscribe, etc.) flows through
// the kernel via these adapters. Capability classes are namespaced "titan.*"
// and are enumerated in helm-oss/reference_packs/titan_hedge_fund.v1.json.
//
// Canonicalization: JCS (RFC 8785) + SHA-256 (helm-oss invariant).
// Signing: Ed25519 (helm-oss invariant).
// Posture: fail-closed — empty allowlist or unreachable kernel ⇒ DENY.
//
// Each capability class lives in a sibling subpackage under
// titan-capability/<name>/ that wires the capability-specific guardian gate
// (e.g. EvidencePack format check, validation-report verdict check, policy-
// bundle SHA pinning).
//
// Mapping table: titan/docs/ai/titan-helm-mapping.md.
// Reference pack: helm-oss/reference_packs/titan_hedge_fund.v1.json.
// Acceptance criteria: titan/docs/ai-native-exit-criteria.md (AIN-11..AIN-18).
package titancapability
