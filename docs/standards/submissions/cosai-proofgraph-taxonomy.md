---
title: "Proposal to CoSAI — ProofGraph Node-Type Taxonomy for Cross-Organizational AI Action Auditing"
author: "Mindburn Labs — HELM OSS maintainers"
date: 2026-04-15
target: Coalition for Secure AI (CoSAI) — Security of AI Agents Workstream
status: Draft for submission
---

# Proposal — ProofGraph Node-Type Taxonomy as a Candidate Schema for Cross-Organizational AI Action Auditing

## Summary

We propose contributing HELM OSS's ProofGraph node-type taxonomy (Apache-2.0) as a candidate schema for CoSAI's Security of AI Agents workstream. The taxonomy is already implemented, tested, and in production use at Mindburn Labs, with formal model-checked invariants covering causal consistency and tenant isolation.

This submission addresses the gap between AI-agent audit logging (currently fragmented, implementation-specific, and non-interoperable across organizations) and the CoSAI workstream's goal of establishing verifiable, cross-org audit semantics.

## The problem CoSAI can help solve

When organization A delegates authority to an AI agent that then operates on organization B's resources, both orgs need a mutually-verifiable audit trace. Today:

1. Each governance framework (HELM, Microsoft AGT, NeMo Guardrails, Guardrails AI, LangSmith, custom-in-house) produces logs in its own format.
2. There is no canonical node-type vocabulary describing what an agent action was, in what causal context, with what authority.
3. Disputes require ad-hoc reconciliation: "our logs say X, theirs say Y, who's right?"

CoSAI is the natural forum for converging on a shared node-type schema because its members include the framework authors, the model providers, and the enterprise adopters whose audit concerns motivate the standardization.

## What HELM contributes

HELM's ProofGraph ([core/pkg/proofgraph/](https://github.com/Mindburn-Labs/helm-oss/tree/main/core/pkg/proofgraph)) is a causal DAG (Lamport-ordered, append-only, content-addressed) with a bounded node-type vocabulary. Every governed agent action in HELM produces exactly one node, linked to its causal parents. The graph is serializable to JSONL + TAR and cryptographically verifiable with Ed25519 signatures per-node plus a rooted manifest hash.

We propose the following node types as a starting vocabulary for CoSAI review:

### Core types (currently implemented)

| Node type | Semantics | Referenced by |
|-----------|-----------|---------------|
| `INTENT` | An agent's proposed action before any governance decision. Contains the tool name, arguments hash, and the principal making the request. | `effects.go`, `guardian.go` |
| `ATTESTATION` | A signed claim about the acting principal, delegation chain, or environment. Typically produced by the identity layer. | `identity/`, `mcp/aip.go` |
| `EFFECT` | The realized outcome of an INTENT that passed governance. References its parent INTENT and carries an output hash + success/failure flag. | `connectors/`, `effects.go` |
| `TRUST_EVENT` | A change to the trust state — a delegation granted, revoked, or narrowed; a principal's reputation score updated. | `identity/continuous_delegation.go`, `trust/` |
| `CHECKPOINT` | A bounded state summary for replay efficiency. Lets verifiers skip verification of pre-checkpoint nodes by trusting the signed summary. | `kernel/` |
| `MERGE_DECISION` | A CRDT merge point between two causal branches (cross-org or multi-agent fork reconciliation). | `proofgraph/merge.go` |
| `ZK_PROOF` | A zero-knowledge proof of policy compliance without revealing inputs. Slot reserved today; full circuit planned Q3 2026. | `crypto/zkp/` |

### Proposed extensions (for CoSAI consideration)

| Node type | Semantics | Rationale |
|-----------|-----------|-----------|
| `FEDERATION_EVENT` | Cross-organizational trust transition (org A delegates to org B's agent; org B accepts and begins operating). | Today this is implicit in TRUST_EVENT chains; making it first-class would simplify federation auditing. |
| `HUMAN_APPROVAL` | Explicit human-in-the-loop decision that a policy required. Carries approver identity + signed timestamp. | Disambiguates auto-approvals from human approvals in forensic reconstruction. |
| `FORENSIC_SEAL` | Administrative freeze applied to a subgraph (e.g., during incident response). Seals can be cryptographically broken only by authorized principals. | Provides an explicit artifact for the "this incident is being investigated; evidence is preserved" state. |

## Why this taxonomy, rather than something else

Three design choices make this taxonomy worth CoSAI's consideration:

1. **Bounded vocabulary**. Eight node types (or eleven with the proposed extensions). Not free-form. Every node must satisfy a type-specific schema, which means cross-org verifiers can process unfamiliar agent frameworks as long as they agree on types.

2. **Causal parents are first-class**. Every node except INTENT must reference one or more parent nodes. This enforces that audits are reasoned about as DAGs, not as rolling event streams. It also makes multi-agent fault attribution computable (Shapley-value attribution at `core/pkg/proofgraph/attribution/`).

3. **TLA+-verified invariants**. The taxonomy's consistency is formally specified in [proofs/ProofGraphConsistency.tla](https://github.com/Mindburn-Labs/helm-oss/blob/main/proofs/ProofGraphConsistency.tla) with the invariant `LamportMonotonic`: every node's sequence number is strictly greater than every parent's. Model-checked nightly via Apalache.

## Interoperability with AGT / other frameworks

We're deliberate about NOT proposing that other frameworks adopt HELM's struct shapes. We propose the *taxonomy* — the set of node types and their causal-parent semantics — as the shared contract. Any framework can serialize its internal representation to JSONL nodes matching this taxonomy; any verifier can read those nodes without caring which framework produced them.

This mirrors how OpenTelemetry handles tracing: the Spec is universal; the SDK implementations are framework-specific.

## Open-sourcing commitments

- HELM ProofGraph implementation: Apache-2.0, at https://github.com/Mindburn-Labs/helm-oss/tree/main/core/pkg/proofgraph.
- TLA+ specs: Apache-2.0, at `proofs/ProofGraphConsistency.tla`, `proofs/TenantIsolation.tla`.
- Node-type schemas: published as JSON Schemas in `protocols/json-schemas/`.
- We commit to tracking CoSAI-driven taxonomy changes in HELM's releases and to accepting contributions back via standard PR review.

## What we are NOT proposing

- Not proposing that CoSAI adopt HELM's TAR serialization or EvidencePack format. Those are implementation choices; other frameworks may pick alternate serializations.
- Not proposing ProofGraph as the only valid audit model. We recognize there are use cases (very high-throughput, very ephemeral) where a DAG is heavyweight. We propose the taxonomy as the **interchange vocabulary**, not the on-disk format.
- Not proposing that HELM be the reference implementation. Any CoSAI-member framework could produce and consume nodes in this taxonomy.

## Open questions for the workstream

We submit these for CoSAI discussion:

1. **Node-type extensibility**: should the vocabulary be closed (v1 fixes the set) or open (vendors can add types with namespace-prefixed IDs)?
2. **Federation semantics**: is `FEDERATION_EVENT` sufficient, or do cross-org transitions need a larger vocabulary (hand-off, attestation-exchange, trust-migration)?
3. **Signature model**: per-node signatures (HELM's choice) vs rooted-manifest-only (lighter, but coarser tamper granularity)?
4. **Privacy vs verifiability tension**: does CoSAI want the standard to require ZK proofs for private traces, or to leave privacy as an implementation choice?

We have strong opinions on 1 and 2 (closed v1, FEDERATION_EVENT sufficient). We are genuinely uncertain on 3 and 4 and want the workstream's broader expertise.

## Request

We ask the CoSAI Security of AI Agents workstream to:

1. **Review** the proposed taxonomy against the workstream's objectives.
2. **Accept or adapt** the core node types (INTENT / ATTESTATION / EFFECT / TRUST_EVENT / CHECKPOINT / MERGE_DECISION / ZK_PROOF) as a draft interchange vocabulary.
3. **Convene** a working session for the proposed extensions (FEDERATION_EVENT, HUMAN_APPROVAL, FORENSIC_SEAL) where competitive and customer input can shape the final set.
4. **Publish** the agreed taxonomy under CoSAI's standards process; Mindburn commits to maintaining HELM's implementation in conformance.

Primary contact: conformance@mindburn.org · Backup: research@mindburn.org

## Appendix — sample serialized node

```json
{
  "id": "0194a7ab-3f2c-7000-8123-...",
  "type": "EFFECT",
  "sequence": 42,
  "actor": "did:agentmesh:alice-agent-v3",
  "parent_ids": ["0194a7ab-3f2c-7000-8120-..."],
  "payload": {
    "tool": "github.create_issue",
    "input_hash": "sha256:c0ffee...",
    "output_hash": "sha256:deadbe...",
    "permit_id": "permit-7f3a9c",
    "success": true
  },
  "created_at": "2026-04-15T18:22:09.417Z",
  "signature": "ed25519:ba3f..."
}
```

This exact shape, with the node types named in this proposal, is the contribution we offer CoSAI for the workstream's consideration.

---

*Signoff*: Mindburn Labs · HELM OSS maintainers · 2026-04-15.
