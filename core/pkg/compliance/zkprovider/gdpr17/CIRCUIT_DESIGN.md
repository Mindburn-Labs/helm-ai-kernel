# GDPR Article 17 ZK Circuit — Design Document

**Status**: Pre-implementation draft for external cryptographic review.
**Circuit version**: `gdpr17-v1-scaffold` (scaffold) → `gdpr17-v1` (on GA).
**Target GA**: 2026-07-15, aligned with EU AI Act high-risk deadline 2026-08-02.

## Problem statement

A data controller receives an erasure request from subject `S` at time `T_E`. Controller deletes personal data and issues an erasure receipt. A data protection authority (DPA), or a downstream processor, later asks: **"Prove you erased S's data at T_E without retaining any personal data afterward."**

Traditional audit produces this proof by showing the raw execution trace to the auditor — but the trace contains every other subject's data, every other decision, and the controller's policy internals. Revealing them to prove one subject's erasure leaks the rest.

**Goal**: a zero-knowledge proof that lets the DPA mechanically verify compliance for subject `S` at time `T_E` without learning anything about other subjects, other decisions, or the controller's policy internals.

## Invariant

Given the public tuple `(policy_hash, T_E, subject_commit)`, there exist private witnesses `(trace, subject_id, secrets)` such that:

1. **Membership**: `subject_commit = Pedersen(subject_id, r)` for some blinding factor `r` in `secrets`.
2. **Post-erasure cleanliness**: for every EFFECT node `E` in `trace` with `E.time > T_E`, `E` does NOT contain `subject_id` in any of its referenced personal-data fields.
3. **Erasure confirmation**: at least one ATTESTATION node `A` exists in `trace` with `A.time ≥ T_E` and `A.type == "erasure_receipt"` and `A.subject == subject_commit`.
4. **Policy gate**: `policy_hash == SHA256(P)` where `P` includes the attribute `gdpr17_enabled == true` at time `T_E`.

Invariant #2 is the delicate part — it quantifies over an unbounded trace. The circuit bounds it by:
- Fixing a maximum trace length `N_MAX` (e.g., 4096 nodes) as a public parameter. Traces longer than this require multi-proof composition (out of scope for v1).
- Using a Merkle tree commitment to the trace such that absence of matches over the full tree is provable in O(log N) circuit gates per negative check.

## Circuit architecture

Backend: **gnark Groth16 over BN254**.

Rationale:
- Groth16 proofs are ~128 bytes, verifier runs in constant time (~3 pairings), suitable for on-chain or lightweight off-chain verification.
- BN254 is widely supported (Ethereum, Polygon, Arbitrum, standard ZK libraries).
- Trade-off: requires trusted setup. Mitigation below.

### Gate-level components

1. **Pedersen commitment check** (~2K gates): recomputes `Pedersen(subject_id, r)` and asserts equality with `subject_commit`.
2. **Merkle root reconstruction** (~10K gates for N_MAX=4096): rebuilds the trace Merkle root from the private trace; asserts it matches the root embedded in the session's evidence pack manifest.
3. **Temporal filter** (per node, ~50 gates × N_MAX = 200K gates): for each trace node, computes `node.time > T_E` and produces a boolean.
4. **Post-erasure cleanliness** (per post-erasure EFFECT node, ~200 gates × expected k = 50K gates): for each EFFECT node after `T_E`, re-derives the personal-data hashes from private secrets + policy and asserts none match the subject's identifier.
5. **Erasure confirmation** (~1K gates): existence proof for at least one ATTESTATION node of type `erasure_receipt` matching subject_commit.
6. **Policy attribute check** (~500 gates): Merkle proof that `gdpr17_enabled == true` within the policy bundle matching `policy_hash`.

Estimated total: ~265K gates. Proof generation: ~3–5 seconds on a modern laptop. Verification: ~10 ms.

### Trusted setup

Groth16 requires a circuit-specific trusted setup. Two paths:

**Option A — participate in Powers of Tau ceremony + per-circuit Phase 2**:
- Phase 1 universal setup reuses ZKSync's published parameters (`bn254-pot25.ptau`, 2^25 constraints).
- Phase 2 Mindburn-specific ceremony: ≥5 geographically distributed contributors (Mindburn Labs, Veridise (auditor), 3 customer / community participants).
- Published contribution hashes on Sigstore Rekor transparency log.

**Option B — move to PLONK**:
- Universal setup (reusable across circuits).
- Simpler ceremony.
- Larger proof size (~500 bytes), slower verification (~30 ms).

**Recommendation**: Option B (PLONK). Universal setup eliminates the per-revision ceremony burden. Proof/verification performance delta doesn't matter at our scale (< 1000 proofs/day forecast).

This decision is explicit input for the external reviewer.

## Public / private input specification

### Public (in PublicInputs):
- `policy_hash`: `bytes32` SHA-256 hash.
- `erasure_time`: uint64 Unix-nanoseconds.
- `subject_commit`: `bytes32` Pedersen commitment.
- `circuit_version`: constant, pinned in the circuit.

### Private (in PrivateInputs):
- `trace`: up to N_MAX bytes, canonical-JSON-encoded ProofGraph node sequence.
- `subject_id`: bytes (typically 32).
- `secrets`: up to N_MAX × 32 bytes of per-node secrets used to blind personal-data fields.
- `blinding_r`: bytes32, Pedersen commitment blinding factor.
- `policy_bundle`: the full P1 bundle matching `policy_hash`.

## Threat model

### In scope (circuit must defend against):
- Malicious prover tries to prove GDPR-17 compliance for a non-erased trace.
- Malicious prover tries to craft a trace with a subject_id different from the committed one.
- Policy attribute malleability (prover inserts `gdpr17_enabled = true` into a bundle that didn't have it).

### Out of scope:
- Controller-level deception (controller executes genuine post-erasure personal-data processing outside HELM governance and hides it from the trace). Solution: organizational control, not cryptographic. HELM's governance is the assumption.
- Subject ID collision (two subjects with identical personal data). Solution: Pedersen commitment binding + unique blinding factors.
- Trusted-setup compromise. Solution: multi-party ceremony per above.

## Test vectors (for post-implementation conformance)

The `testvectors/` subdirectory will hold canonical test vectors the real circuit must reproduce:

1. `tv-01-erased-clean/` — legitimate erasure + clean post-erasure trace → proof should VERIFY.
2. `tv-02-post-erasure-leak/` — post-erasure EFFECT still contains subject data → proof should FAIL.
3. `tv-03-no-receipt/` — no erasure_receipt ATTESTATION → proof should FAIL.
4. `tv-04-policy-disabled/` — `gdpr17_enabled == false` in the bundle → proof should FAIL.
5. `tv-05-wrong-subject/` — prover uses correct trace but a different subject_id than subject_commit → proof should FAIL.
6. `tv-06-timestamp-spoof/` — prover backdates EFFECT time past erasure → proof should FAIL (signature binding).
7. `tv-07-empty-trace/` — zero-length trace → proof VERIFIES trivially (vacuous truth).

Each vector is a `(public_inputs.json, private_inputs.json, expected.json)` triple.

## Performance targets

| Operation | Target | Hard ceiling |
|-----------|--------|--------------|
| Prover (full trace, N=4096) | ≤ 5s | ≤ 15s |
| Verifier | ≤ 100ms | ≤ 500ms |
| Proof size | ≤ 1 KB (Groth16) or ≤ 1.5 KB (PLONK) | ≤ 4 KB |
| Prover memory | ≤ 4 GB | ≤ 16 GB |

## Integration surface

- **CLI**: `helm zk prove --pack evidence.tar --subject <commit> --erasure-time <ts> --out proof.bin`
- **CLI**: `helm zk verify proof.bin --policy-hash <hex> --subject <commit> --erasure-time <ts>`
- **Go API**: `gdpr17.Prove(ctx, priv, pub) Proof` / `gdpr17.Verify(ctx, proof, pub) error`.
- **WASM verifier**: compiled via `GOOS=js GOARCH=wasm go build`; served by the OSS-lite dashboard at `try.mindburn.org` as an optional "ZK Verification" tab (post-GA).
- **Commercial API**: `/v1/zk/prove` (billed per proof) and `/v1/zk/verify` (free; trust-enhances the HELM brand). Phase 5 item P5-05.

## Open questions for the external reviewer

1. PLONK vs Groth16 — our preference is PLONK; do they agree?
2. N_MAX = 4096 — is this the right bound for the realistic HELM session-size distribution? Should we allow proof composition for longer traces?
3. Pedersen commitment curve — BN254 G1 vs Jubjub? Trade-offs in integration with gnark.
4. Trusted-setup ceremony — if we go Groth16, what's the minimum participant set they'd accept for a regulator-admissible ceremony?
5. Side channels — anything we should defend against in the prover's runtime (constant-time arithmetic, timing-attack resistance)?

## Deliverables at real-circuit ship (Q3 2026)

- `circuit.go` — real gnark circuit definition, no `ErrNotImplemented` returns.
- `prover.go` — gnark prover wrapping the circuit.
- `verifier.go` — gnark verifier.
- `wasm/verifier.wasm` — compiled verifier for browser use.
- `testvectors/*.json` — the 7 vectors above, plus any from the reviewer.
- `PerformanceReport.md` — benchmark results from a production-like machine.
- `AuditReport.pdf` — external reviewer's signed findings + fix attestations.
- Updated `VERSION`, `CHANGELOG.md` v0.6.0 entry, and `docs/research/zk-gdpr17.md`.

## References

- arXiv 2512.14737 — ZK audit for Internet of Agents (paired with MCP).
- arXiv 2502.18535 — ZKMLOps survey (framework convergence).
- arXiv 2511.17118 — Constant-size cryptographic evidence structures.
- gnark library: https://github.com/Consensys/gnark
- ZKProof community: https://zkproof.org
- Production plan item K: `/Users/ivan/.claude/plans/helm-agt-production-deployment.md#k-p4-03--zk-gdpr-article-17-circuit`
- Reviewer shortlist: `docs/decisions/0003-zk-cryptographic-reviewer.md`
