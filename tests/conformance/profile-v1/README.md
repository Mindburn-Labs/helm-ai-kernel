# HELM Conformance Profile v1

**Status**: Draft v1.0.0 · **Last updated**: 2026-04-15 · **Successor to**: none (this is the first formal profile)

This directory defines the minimum surface any implementation must ship to call itself **HELM-conformant v1**. It is the public contract the certification program (roadmap P5-03) uses as its acceptance test.

## Why this profile exists

HELM is not just a binary — it is an *architecture* for fail-closed AI execution governance. For the architecture to have interoperable meaning across OSS adopters, commercial integrators, and external re-implementations, we need a **formal acceptance suite**. This profile is that suite.

Without it:
- Two vendors can both say "HELM-compatible" and mean different things.
- A certification badge has no mechanical basis.
- Federation (the cross-org trust plane) has no agreed verification predicate.

With it:
- `make crucible-profile-v1` is the single source of truth.
- Any externally-built implementation passes the same suite before claiming conformance.
- The `helm` certification service (P5-03) runs this suite against submissions.

## The six-axis profile

Conformance is not a single bit — it's six independent invariants. Implementations pass if they satisfy **all six** at v1.

| Axis | Property | Verification |
|------|----------|--------------|
| **1. Fail-closed firewall** | Empty allowlist must deny all; nil dispatcher must error, not silently pass. | `checklist.yaml#firewall` |
| **2. Canonical receipts** | JCS-canonical manifest + SHA-256 chain; same inputs → identical bytes across platforms. | `checklist.yaml#receipts` |
| **3. Causal ProofGraph** | Nodes carry Lamport sequence + parent_ids; DAG is reconstructable from JSONL. | `checklist.yaml#proofgraph` |
| **4. Delegation semantics** | P2 overlays narrow P1; P1 narrows P0. Non-widening invariant holds under TLA+ (`DelegationModel.tla`). | `checklist.yaml#delegation` |
| **5. EvidencePack round-trip** | `export(session)` followed by `verify(pack)` on any platform returns PASS; tamper of one byte returns FAIL. | `checklist.yaml#evidencepack` |
| **6. Deterministic replay** | `replay(pack)` reproduces every decision bit-identically; any divergence is an invariant breach. | `checklist.yaml#replay` |

## How implementations are tested

### Reference implementation (`helm-oss` itself)

The reference HELM binary must pass its own profile. That's the first conformance claim HELM makes about itself:

```bash
make crucible-profile-v1   # runs this suite against helm-oss core
```

### External implementations

A third-party adopter submits their binary to the certification service (P5-03), which runs:

1. The Go-level acceptance tests in `profile_test.go` (treats the external binary as a subprocess).
2. The TLA+ invariants via Apalache CI (the invariants are implementation-agnostic).
3. The golden-fixture replay suite (below).

Passing all three produces a signed `HELM-Conformant v1` badge that the adopter can publish alongside their release.

## Golden fixtures

`testdata/` contains 6 canonical EvidencePacks — one per axis — with known-good outputs recorded. Every conformant implementation must produce these exact outputs:

| Fixture | Exercises | Expected result |
|---------|-----------|-----------------|
| `fixture-01-fail-closed.tar` | Firewall axis | All 5 embedded calls DENY with correct reason codes |
| `fixture-02-canonical.tar` | Canonical-receipt axis | SHA-256 manifest digest matches `fixture-02-digest.txt` |
| `fixture-03-causal.tar` | ProofGraph axis | Lamport traversal of ProofGraph matches `fixture-03-order.txt` |
| `fixture-04-delegation.tar` | Delegation axis | Narrowing-only property holds; widening attempts DENY |
| `fixture-05-export.tar` | EvidencePack axis | Export + tamper + re-verify returns FAIL |
| `fixture-06-replay.tar` | Replay axis | Replay matches; divergence test returns EXIT=1 |

Fixtures are produced deterministically by `make regen-profile-v1-fixtures`. Regeneration requires the reference `helm` binary at a tagged release commit.

## Versioning

- **v1.x** — this profile. Additive changes only (e.g., new checklist item). Existing conformance claims remain valid.
- **v2** — not planned before ≥3 adopters have certified against v1 and returned at least one round of feedback. v2 will be a breaking change; v1 certificates retain validity.

## Files in this directory

- `README.md` — this document.
- `checklist.yaml` — machine-readable acceptance criteria.
- `profile_test.go` — Go-level acceptance tests (skeleton; extend as golden fixtures are published).
- `testdata/` — golden fixtures (publish separately per release).

## Relationship to other HELM artifacts

- `protocols/spec/PROTOCOL.md` — the formal wire-format and semantics spec. Reference for *what* implementations must do.
- `protocols/spec/evidence-pack-v1.md` — the EvidencePack format spec. Referenced by axis 2 and axis 5 of this profile.
- `proofs/GuardianPipeline.tla` + `proofs/DelegationModel.tla` — formal model-checked invariants. Referenced by axes 1 and 4.
- `.github/workflows/apalache.yml` — CI that proves those invariants on every PR.

## Submission checklist for external adopters

1. Run `make crucible-profile-v1` locally. All axes green.
2. Publish your implementation's SBOM + provenance.
3. Submit to the HELM certification service (P5-03) with:
   - Binary or container image.
   - Matching test outputs for each golden fixture.
   - Statement of conformance with axes 1–6 explicitly attested.
4. Pass the independent reproduction step on the certification runner.
5. Receive the signed `HELM-Conformant v1` badge + registry entry at `certified.mindburn.org`.

---

*Phase 4 conformance deliverable. This profile is the mechanical basis for the Phase 5 certification service.*
