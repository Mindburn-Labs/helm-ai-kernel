---
title: HELM Policy Composition — Why P0/P1/P2 is Optimal
---

# HELM Policy Composition — Why P0/P1/P2 is Optimal

**Thesis**: HELM's three-layer policy composition (P0 hard ceilings → P1 signed governance bundles → P2 per-session overlays) is not a design choice made in isolation — it independently matches the theoretically optimal layering identified in the governance-as-code literature. This document traces the argument with citations.

## The three layers

| Layer | Role | Authority | Mutability |
|-------|------|-----------|------------|
| **P0 — Ceilings** | Absolute limits the system cannot exceed regardless of delegation or request | Root (hardware/kernel operator) | Immutable at runtime; changes require signed release |
| **P1 — Bundles** | Signed governance policy compiled to WASM/CEL bytecode; organizational defaults and obligations | Governance signer (corporate / regulatory) | Versioned, hash-bound, replayable; mutable via signed upgrade |
| **P2 — Overlays** | Per-session narrowing only (never widening); delegation-scoped | Session initiator within their delegated authority | Session-local; expires with session |

Precedence: **P0 > P1 > P2**. P2 can narrow within P1; P1 operates within P0; neither can escape P0.

## The academic argument

Three independent lines of research converge on three-layer composition as the expressive minimum.

### 1. Path-based policies require separate composition from point policies

arXiv [2603.16586](https://arxiv.org/abs/2603.16586) — *"Runtime Governance for AI Agents: Policies on Paths"* — formalizes compliance policies as deterministic functions `(agent identity, partial execution path, proposed action, org state) → violation probability`. It proves **path-based policies are strictly more expressive than stateless per-action policies**.

This drives the need for *at least two* policy layers:
- A path-agnostic layer (point constraints on actions)
- A path-aware layer (session-history-aware constraints)

HELM's P0 (point ceilings) and P1+P2 (path-aware bundles that see session history) fit this split exactly.

### 2. Compliance policy must separate from operational policy

arXiv [2604.05229](https://arxiv.org/html/2604.05229) — *"From Governance Norms to Enforceable Controls"* — studies how abstract compliance norms translate into enforceable runtime controls. The paper describes a **layered translation**:

```
Abstract norms (regulation, statute)
        ↓ interpretation
Concrete controls (signed, organization-authored)
        ↓ deployment
Runtime guardrails (per-session execution constraints)
```

The paper argues this three-layer composition is the *minimum* needed to preserve authority across the translation chain without collapsing layers (which loses traceability) or adding more layers (which introduces ambiguity about precedence).

HELM's P0 = hard norms baked into the kernel; P1 = signed interpretations per tenant/regulator; P2 = per-session narrowing. The layers match 1:1.

### 3. Adaptive policies require a narrow-only rewrite layer

arXiv [2601.10440](https://arxiv.org/html/2601.10440) — *"AgentGuardian: Learning Access Control Policies"* — shows that context-aware access-control policies require a **narrow-only rewrite layer** at request time. Without it, adaptive policies either become un-auditable (because every session mutates global state) or untrackable (because narrowing must compose with a signed base layer that cannot move under the session).

HELM's P2 is exactly that layer: **narrowing only, never widening**; bounded by P1 in scope; expires with the session. This is verified in the TLA+ spec for delegation ([proofs/DelegationModel.tla](../../proofs/DelegationModel.tla)) which encodes the non-widening invariant.

### 4. Governance-as-a-service boundary

arXiv [2508.18765](https://arxiv.org/abs/2508.18765) — *"Governance-as-a-Service"* — examines external multi-agent compliance frameworks (what HELM is). It identifies that systems with **fewer than three layers** collapse compliance and operational concerns and cannot handle cross-organizational federation without leaking one tenant's policy into another's execution envelope.

HELM's federation story (Phase 5 roadmap item P5-06) rests on tenants composing their own P1 + P2 over a shared P0 root-of-trust. Without the three-layer split this composition is not expressible.

## What lower-layer systems miss

Microsoft Agent Governance Toolkit's `PolicyEvaluator` is a **single-layer** YAML/OPA/Cedar evaluator: each policy is evaluated against each action with no formal composition precedence, no hash-binding between layers, and no narrowing-only rewrite layer. Per arXiv 2604.05229 and 2601.10440 this flattening loses two of the three axes of expressiveness.

Specifically AGT cannot:
- Prove a per-session narrowing does not widen the signed bundle beneath it.
- Distinguish a regulator-mandated ceiling from a tenant-authored rule.
- Compose tenant policies in a federation without one tenant's overlay leaking into another.

This is an architectural gap, not a configuration gap.

## HELM's implementation

| Layer | File | Semantics |
|-------|------|-----------|
| P0 | [core/pkg/kernel/ceilings.go](../../core/pkg/kernel/) + Guardian Freeze/Context gates | Kernel-enforced absolute limits |
| P1 | [core/pkg/policy/](../../core/pkg/policy/) + [reference_packs/*.v1.json](../../reference_packs/) | Signed bundles with CEL + WASM evaluation via wazero |
| P2 | Per-session overlay in [core/pkg/identity/delegation.go](../../core/pkg/identity/) | Narrowing-only; verified non-widening via TLA+ |

Hash-binding: each P1 bundle has a SHA-256 content hash referenced in decision records ([core/pkg/contracts/](../../core/pkg/contracts/)) so a replay at time T sees the bundle that was active at T, not the current bundle. This is what gives HELM decisions *forensic replay* — a property single-layer systems cannot provide.

## Formal verification

The non-widening invariant (P2 cannot widen P1; P1 cannot widen P0) is stated as a TLA+ invariant at [proofs/DelegationModel.tla](../../proofs/DelegationModel.tla). It is model-checked by the `apalache.yml` workflow on every PR to `core/pkg/identity/`, `core/pkg/kernel/`, `proofs/`.

Invariants:
- `NarrowingOnly`: for all sessions s, `P2(s).scope ⊆ P1(s).scope ⊆ P0.scope`.
- `AuthorityStable`: signer of P1 at time T cannot be forged at T+k without an external key compromise.
- `CeilingRespected`: no decision D produces a permit allowing an effect outside `P0.scope`.

## Implications

1. **Policy upgrades are proofs, not operations.** A P1 bundle upgrade is a content-addressed, signed object; replay of past decisions reveals which bundle was active. Diffing a past decision against the current bundle requires explicit action.
2. **Federation is composable.** Tenant A's P1 + P2 can coexist with tenant B's P1 + P2 under a shared P0, because the narrowing-only semantics prevent cross-tenant leakage. AGT's flat model cannot express this safely.
3. **Path awareness is first-class.** P1 bundles can reference session history because HELM's guardian passes `SessionHistory` through the decision context (per [P4-01 / session_history_test.go](../../core/pkg/guardian/session_history_test.go)).

## Further reading

- HELM's policy WASM runtime (wazero-based, deterministic): [core/pkg/policy/wasm/](../../core/pkg/policy/wasm/)
- Guardian's role in gating: [docs/architecture/guardian-pipeline.md](../architecture/guardian-pipeline.md)
- Compliance enforcement vs mapping: [docs/compliance/enforcement-vs-mapping.md](../compliance/enforcement-vs-mapping.md)
- TLA+ specs: [proofs/](../../proofs/)
- Research plan (58-paper survey): [docs/research/](.)

---

*Part of the Phase 1 packaging gate. Last updated 2026-04-15.*
