---
title: "Proposal to LF AI & Data — HELM Conformance Profile v1 as a Working-Group Draft"
author: "Mindburn Labs — HELM OSS maintainers"
date: 2026-04-15
target: LF AI & Data Foundation — Trusted AI Committee (or appropriate host TAC)
status: Draft for submission
---

# Proposal — HELM Conformance Profile v1 as a LF AI & Data Working-Group Draft

## Summary

We propose contributing the HELM Conformance Profile v1 (released under Apache-2.0) as a working-group draft under LF AI & Data. The profile is a six-axis acceptance suite that defines the minimum architectural surface any implementation must ship to credibly call itself an "AI execution governance" system. It is specified in a machine-readable YAML checklist, backed by formal TLA+ invariants model-checked in CI, and includes golden fixtures for deterministic conformance testing.

The ask: adopt the profile under LF AI & Data governance so that neutrality of the standard is assured and adoption across competing frameworks (Mindburn HELM, Microsoft AGT, NVIDIA NeMo Guardrails, Guardrails AI, community implementations) can be coordinated through an existing, trusted body.

## Why LF AI & Data is the right host

The agent governance space is crowded, contested, and commercially relevant. Any single vendor — including ourselves — is a poor steward of a neutral standard. LF AI & Data:

1. Has a mature TAC/project process that balances sponsor and community interests.
2. Hosts standards for adjacent domains (PyTorch Foundation, OpenLineage, Fairlearn) with similar vendor-neutrality requirements.
3. Provides the legal infrastructure (LFAI IP policy, contribution agreements) that Apache-2.0 artifacts map cleanly onto.
4. Has an established relationship with CoSAI (see our CoSAI proposal for the ProofGraph node-type taxonomy) — which we hope can run in parallel on the auditing-vocabulary side while this profile addresses the minimum-conformance surface.

Other potential hosts we considered and why LF AI & Data is better:
- **OWASP**: excellent for threat taxonomy (we've submitted ASI-01–10 mapping to the Agentic AI WG) but OWASP's process is optimized for risk guidance, not implementation-conformance standards.
- **IETF**: too protocol-oriented; Conformance Profile v1 is architectural.
- **ISO**: too slow; the agent space evolves on 6-month cycles.
- **W3C**: adjacent (we rely on W3C DID) but the core concerns here are execution governance, not identifier resolution.

## What Conformance Profile v1 specifies

Six axes, each a formally-defined invariant an implementation must preserve:

1. **Fail-closed firewall** — empty allowlist denies; nil dispatcher surfaces as fail-closed error, not silent pass.
2. **Canonical receipts** — JCS-canonical manifest + SHA-256 chain + Ed25519 signatures, byte-identical across platforms.
3. **Causal ProofGraph** — Lamport-ordered DAG with `parent_ids`; reconstructable from JSONL.
4. **Delegation semantics** — narrowing-only (TLA+ invariant `NarrowingOnly`): P2 ⊆ P1 ⊆ P0 always.
5. **EvidencePack round-trip** — export + verify is deterministic; one-byte tamper returns FAIL.
6. **Deterministic replay** — replay reproduces every decision bit-identically; any divergence is an invariant breach.

The full specification ships in the HELM OSS repository at `tests/conformance/profile-v1/`:

- `README.md` — human-readable profile description, adopter flow, badge program.
- `checklist.yaml` — machine-readable acceptance criteria (14 checks across six axes, each with verification kind + target).
- `profile_test.go` — Go acceptance runner (guards checklist well-formedness; extensible).
- `testdata/` — golden fixtures (six canonical EvidencePacks, one per axis) for cross-implementation conformance testing.

Paired with:
- `protocols/spec/PROTOCOL.md` — the wire-format and semantics spec (v1.0.0 Draft).
- `protocols/spec/evidence-pack-v1.md` — the EvidencePack format spec.
- `proofs/*.tla` — six TLA+ specifications formally proving the invariants, model-checked nightly via Apalache.

## What we propose contributing

1. **The profile specification** (README + checklist.yaml) under Apache-2.0, for LFAI to host as the reference document.
2. **The TLA+ specifications** under Apache-2.0, so the formal invariants travel with the spec.
3. **The golden fixtures** (six canonical EvidencePacks) under CC0, so any implementation can use them without license friction.
4. **A reference implementation** in HELM OSS (github.com/Mindburn-Labs/helm-oss) that continuously proves v1 conformance via CI.
5. **A draft certification process** (badge program + submission flow) that LFAI can take over, adapt, or reject in favor of its own conformance program.

## What we are NOT proposing

- **Not proposing** HELM as the only conformant implementation. The specification is implementation-agnostic — any framework (including commercial toolkits, community projects, research prototypes) can certify by passing the checklist.
- **Not proposing** LFAI adopt HELM's Go packaging or binary formats. The profile describes architectural invariants, not implementation choices.
- **Not proposing** that existing framework contributors change their frameworks. A framework can declare non-conformance and still be useful; the profile lets users and enterprise buyers make informed choices.
- **Not proposing** a hostile takeover. We'd like LFAI to own the specification; Mindburn retains HELM OSS as our implementation.

## Why this matters for the LF AI & Data ecosystem

Enterprise adoption of AI agents is currently blocked on two questions procurement teams keep asking:

1. *"What does it mean for an agent to be 'governed'? Everyone claims it."*
2. *"If we adopt framework A today and framework B next year, can we use the same audit trail?"*

A neutrally-hosted Conformance Profile v1 gives both questions a machine-checkable answer. Procurement can require v1 conformance in RFPs; implementors have a clear target; auditors have a known acceptance criterion.

Without a neutral standard, the space trends toward winner-take-all dynamics favoring the largest ecosystem player (currently Microsoft AGT with its April 2026 v3.1.0 Public Preview release). That's a suboptimal outcome for open-source agent frameworks and enterprise buyers alike.

## Governance model we'd propose

If LFAI accepts:

- A working group (2-5 initial members including at least one non-Mindburn maintainer) drafts v1.0.0 Final from the current v1.0.0 Draft.
- TAC review and approval under standard LFAI project process.
- Mindburn commits to implementing subsequent working-group-directed changes in HELM OSS and participating in the WG.
- First formal release target: 2026-Q3 (align with EU AI Act high-risk deadline 2026-08-02).
- v2 cannot be initiated until at least 3 independent implementations certify against v1.

## Open questions for LFAI to steer

1. **Venue**: Committee (Trusted AI), project (new incubation), or joint with an existing project (OpenLineage overlap)?
2. **IP/CLA**: is Apache-2.0 + DCO the working-group baseline, or does LFAI prefer CCLA?
3. **Relationship to CoSAI**: we've separately proposed the ProofGraph node-type taxonomy to CoSAI. Should these two efforts be explicitly linked, merged, or coordinated?
4. **Relationship to existing LFAI efforts**: are there OpenLineage, AI Fairness 360, or Trusted AI assets that would overlap or consume the profile?

## Request

We ask LF AI & Data to:

1. **Acknowledge receipt** of this proposal.
2. **Route** to the appropriate TAC / committee for evaluation.
3. **Schedule** an introductory technical deep-dive where Mindburn can walk the WG through the specification, TLA+ proofs, and golden fixtures.
4. **Decide** on venue and IP terms within a reasonable review window (we target Q2 2026 response, recognizing this is ambitious for a standards body).

Primary contact: conformance@mindburn.org · Alternate: research@mindburn.org

## Appendix — proof artifact inventory

All artifacts are current in the HELM OSS repo as of 2026-04-15 commit tag `0.4.0`:

| Artifact | Path | License |
|----------|------|---------|
| Profile README | `tests/conformance/profile-v1/README.md` | Apache-2.0 |
| Machine-readable checklist | `tests/conformance/profile-v1/checklist.yaml` | Apache-2.0 |
| Go acceptance runner | `tests/conformance/profile-v1/profile_test.go` | Apache-2.0 |
| Golden fixtures | `tests/conformance/profile-v1/testdata/` | CC0 (planned) |
| Wire-format spec | `protocols/spec/PROTOCOL.md` | Apache-2.0 |
| EvidencePack format spec | `protocols/spec/evidence-pack-v1.md` | Apache-2.0 |
| TLA+ specifications | `proofs/*.tla` (6 specs) | Apache-2.0 |
| Apalache CI workflow | `.github/workflows/apalache.yml` | Apache-2.0 |
| Reference implementation | Full HELM OSS repo | Apache-2.0 |

Total contribution surface: ~240 KB of machine-readable specification + ~800 KB of Go reference implementation (governance kernel paths only; the full HELM OSS repo is larger).

---

*Signoff*: Mindburn Labs · HELM OSS maintainers · 2026-04-15.
