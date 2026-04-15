---
title: "Proposal to OWASP Agentic AI Top 10 Working Group — Enforcement-Layer Reference Implementation"
author: "Mindburn Labs — HELM OSS maintainers"
date: 2026-04-15
target: OWASP Agentic AI Security Working Group
status: Draft for submission
---

# Proposal — Enforcement-Layer Reference Implementation for OWASP Agentic Top 10

## Summary

We propose contributing HELM OSS's code-level enforcement mappings and the Conformance Profile v1 acceptance suite (both released under Apache-2.0) as a reference implementation artifact for the OWASP Agentic AI Top 10. The goal is to give the working group and implementers a ground-truth anchor for "what does a *mitigation* actually look like in code?" — not a taxonomy document, not a vendor checklist, but executable tests + invariants that can be lifted into any implementation.

This submission contains:

1. A gap analysis of the current ASI-01…ASI-10 mitigation guidance against shipping enforcement code.
2. A mapping from each ASI risk to HELM's code path + test + TLA+ invariant.
3. A proposed standardization artifact: a minimum-enforceable-surface checklist tied to the six-axis HELM Conformance Profile v1.

## Context

The 2025 OWASP Agentic AI Top 10 established the risk taxonomy (ASI-01 Goal Hijacking through ASI-10 Rogue Agents). Current guidance covers *what* to mitigate. It does not yet cover *how much code* constitutes a credible mitigation, nor how implementations should be tested for mitigation completeness.

We have built HELM OSS (Apache-2.0, github.com/Mindburn-Labs/helm-oss) as a fail-closed AI execution substrate. In shipping it, we have developed code paths, tests, and formal proofs for each ASI risk. We offer these as a baseline the working group may adopt, extend, or reject — whichever serves the standard better.

## Proposed artifact: enforcement-layer reference

For each OWASP Agentic risk, we propose the working group include (in future Top 10 guidance):

1. A **code reference** — a concrete file:line or test name showing a credible enforcement implementation.
2. An **invariant** — a machine-checkable property (ideally formal, e.g., TLA+) that a compliant implementation preserves.
3. An **acceptance check** — a shell/Go-runnable test producing a pass/fail.

HELM contributes the reference, invariant, and check for all 10 risks. We do not propose HELM's code as the only acceptable mitigation — we propose it as the anchor that removes ambiguity about what "covered" means. Other toolkits can point at different code with the same invariants and still satisfy the standard.

### Mapping table (condensed — full table in appendix A)

| Risk | HELM code reference | Invariant | Acceptance check |
|------|---------------------|-----------|------------------|
| ASI-01 Prompt Injection | `core/pkg/threatscan/ensemble.go` | Ensemble voting ANY/MAJORITY/UNANIMOUS strategies | `TestEnsembleScanner_*` |
| ASI-02 Tool Poisoning | `core/pkg/mcp/rugpull.go` + `docscan.go` | TOFU fingerprint → any change produces RugPullFinding | `TestRugPullDetector` + `TestDDIPEScan` |
| ASI-03 Excessive Permission | `core/pkg/effects/types.go` | Effect permits are single-use, nonce-verified, scope-bound | `TestEffectPermit_SingleUse` |
| ASI-04 Insufficient Validation | `core/pkg/guardian/guardian.go` | TLA+ `GuardianPipeline.tla` proves 6-gate ordering + fail-closed | Apalache model-check |
| ASI-05 Improper Output | `Guardian.EvaluateOutput()` | Output quarantine gate + source-channel tagging | `TestGuardian_OutputQuarantine` |
| ASI-06 Resource Overborrowing | `core/pkg/budget/` + `core/pkg/kernel/memory_integrity.go` | ACID-locked budget ceilings + SHA-256 memory integrity | `TestBudget_FailClosed` |
| ASI-07 Cascading Effects | `core/pkg/effects/circuitbreaker.go` + `core/pkg/proofgraph/` | Causal DAG enables Shapley-value blast-radius attribution | `TestCircuitBreaker_OpenOnBurst` |
| ASI-08 Data Exposure | `core/pkg/firewall/` + `core/pkg/crypto/sdjwt/` | Empty-allowlist-denies + selective-disclosure JWT | `TestFirewall_EmptyAllowlistDenies` |
| ASI-09 Plugin/Tool Insecurity | `core/pkg/mcp/gateway.go` + `core/pkg/pack/verify_capabilities.go` | SkillFortify static capability-envelope proofs + pack provenance | `TestSkillFortify_*` + `TestProvenance_Ed25519` |
| ASI-10 Insufficient Monitoring | `core/pkg/evidencepack/` + `core/pkg/proofgraph/` + `core/pkg/guardian/otel.go` | JCS-canonical + Ed25519-signed + Lamport-ordered + CloudEvents export | `TestEvidencePack_RoundTrip` |

## Proposed standardization: the six-axis conformance profile

We have drafted a formal Conformance Profile v1 (tests/conformance/profile-v1/ in the HELM OSS repo) that tests whether an implementation satisfies six independent architectural invariants:

1. **Fail-closed firewall** — empty allowlist denies all; nil dispatcher surfaces as fail-closed error.
2. **Canonical receipts** — JCS-canonical manifests + SHA-256 chain + Ed25519 signatures, byte-identical across platforms.
3. **Causal ProofGraph** — Lamport-ordered DAG with parent_ids; reconstructable from JSONL.
4. **Delegation semantics** — narrowing-only (TLA+ invariant `NarrowingOnly`): P2 ⊆ P1 ⊆ P0 always.
5. **EvidencePack round-trip** — export + verify is deterministic; one-byte tamper returns FAIL.
6. **Deterministic replay** — replay reproduces every decision bit-identically; any divergence is an invariant breach.

We propose the working group consider adopting these axes (or a subset, or variants) as the **minimum verifiable surface** any Agentic-Top-10-mitigating implementation must satisfy. This transforms the Top 10 from a taxonomy into a testable contract.

Why six axes and not more?
- Fewer axes collapse meaningful architectural distinctions (see Microsoft Agent Governance Toolkit v3.1.0 — a single-layer PolicyEvaluator cannot express narrowing-only delegation; see our internal analysis at [dreamy-sniffing-brooks](https://github.com/Mindburn-Labs/helm-oss/blob/main/docs/comparisons/agt-april-2026.md)).
- More axes add surface that implementers can trivially check the box on without corresponding architectural property.
- Six maps 1:1 to the TLA+ invariants that are currently model-checked nightly in a production reference implementation.

## What we are NOT proposing

- HELM is not the only valid implementation. We submit the code so the working group can reason about what a credible enforcement looks like at the code level, not to establish HELM as canonical.
- We are not proposing HELM's dataclass shapes, package names, or binary formats as the standard. The *invariants* matter; the data carriers do not.
- We are not proposing that the Top 10 itself change. The taxonomy (ASI-01 through ASI-10) is well-formed. What we offer supplements it with enforcement-layer clarity.

## Open-sourcing commitments

- HELM OSS code: Apache-2.0, present URL: https://github.com/Mindburn-Labs/helm-oss
- Conformance Profile v1 spec: Apache-2.0, bundled in the repo at `tests/conformance/profile-v1/`.
- TLA+ specs: Apache-2.0, at `proofs/*.tla` in the repo.
- Golden fixtures: will be published as tagged release artifacts; Apache-2.0.
- We commit to maintaining these artifacts in lockstep with HELM OSS minor releases and to accepting contributions to extend the checklist via standard PR review.

## Request

We ask the working group to:

1. **Accept or reject** the concept of code-level enforcement references in future OWASP Agentic Top 10 guidance.
2. If accepted, **allocate review slots** for HELM's proposed mapping table (Appendix A below, condensed above) — either to adopt, extend, or counter-propose alternatives.
3. **Consider the Conformance Profile v1** for inclusion (in whole or part) in the next Top 10 revision's implementation guidance section.

We are available for presentation and Q&A at the working group's convenience. Primary contact: conformance@mindburn.org.

## Appendix A — full ASI-01 through ASI-10 mapping

(Full expanded version with code file:line for every claim. Available at `docs/security/owasp-agentic-top10-coverage.md` in the HELM OSS repo, 329 lines, cross-referenced against code. Reproduced in full on request.)

## Appendix B — machine-readable checklist

(`tests/conformance/profile-v1/checklist.yaml` in the HELM OSS repo. 180 lines YAML. Enumerates every check by id, axis, verification kind, and reference. Reproduced in full on request.)

## Appendix C — TLA+ invariants referenced

| Spec | Invariant | Proves |
|------|-----------|--------|
| `GuardianPipeline.tla` | `FailClosed` | No decision path produces ALLOW when any gate returns DENY |
| `DelegationModel.tla` | `NarrowingOnly` | ∀ sessions s: P2(s).scope ⊆ P1(s).scope ⊆ P0.scope |
| `ProofGraphConsistency.tla` | `LamportMonotonic` | Every node's sequence > every parent's sequence |
| `TenantIsolation.tla` | `NoCrossTenantLeak` | Tenant A's P1 never evaluated in tenant B's session |
| `TrustPropagation.tla` | `TrustIsSourceTraceable` | Every trust decision has a signed path to a root-of-trust |
| `CSNFDeterminism.tla` | `CSNFDeterministic` | Same inputs → same canonical-structured-normal-form output |

Each is model-checked on every PR via `.github/workflows/apalache.yml`.

## Signoff

Mindburn Labs · HELM OSS maintainers · 2026-04-15

We thank the OWASP Agentic AI Security Working Group for the taxonomy work and look forward to contributing at the enforcement-layer detail where our production experience is strongest.
