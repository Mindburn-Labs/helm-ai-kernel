// Package gdpr17 is a SCAFFOLD for a zero-knowledge proof of GDPR Article 17
// ("right to erasure") compliance.
//
// STATUS: 2026-04-15 — Interface scaffold only.
// Real gnark circuit + prover + verifier land in Q3 2026 after external
// cryptographic review (see docs/decisions/0003-zk-cryptographic-reviewer.md
// and the production-deployment-plan item K).
//
// DO NOT USE IN PRODUCTION.
//
// Every entry point in this package panics with a clear "not implemented"
// message. The purpose of this scaffold is to:
//
//  1. Define the stable Go interface so downstream code (CLI, dashboard,
//     commercial ZK service, regulator playground) can be built against it
//     while the circuit is being engineered.
//  2. Document the circuit design (see CIRCUIT_DESIGN.md in this directory)
//     for pre-implementation review by the selected external auditor.
//  3. Provide test-vector structure so the first real implementation can be
//     compared against a canonical set of inputs and expected outputs.
//
// The public API defined here is shaped around gnark's Circuit / Witness /
// Proof types without depending on gnark directly (the scaffold avoids
// pulling the gnark dependency until the real circuit lands, to keep the
// module graph small and the SBOM clean).
//
// INVARIANT THE FUTURE CIRCUIT WILL PROVE
// ----------------------------------------
//
// Given:
//   - policy_hash    : SHA-256 of the active P1 policy bundle at the time of
//     the erasure event (public).
//   - erasure_time   : Unix-nanosecond timestamp of the erasure event (public).
//   - subject_commit : Pedersen commitment to the subject identifier (public).
//   - trace          : ProofGraph node sequence for the session (private).
//   - subject_id     : raw subject identifier (private).
//   - secrets        : per-record secrets used to re-derive personal-data hashes (private).
//
// The circuit proves:
//
//	For every EFFECT node E in trace with E.time > erasure_time:
//	  - E does NOT reference subject_commit's subject_id directly, AND
//	  - any ATTESTATION referencing subject_commit after erasure_time is of
//	    type "erasure_receipt".
//
//	AND the active policy at erasure_time includes the invariant
//	`gdpr17_enabled == true`.
//
// Public signals emitted: {policy_hash, erasure_time, subject_commit, circuit_version}.
// Verifier accepts without learning: trace contents, subject_id, secrets.
//
// See CIRCUIT_DESIGN.md for the full gate-level specification.
package gdpr17
