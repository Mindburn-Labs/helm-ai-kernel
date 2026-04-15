---
title: "Architecture"
description: "HELM's execution kernel, platform boundary, and organizational control model."
category: overview
order: 3
status: Canonical
audience: [Developers, Auditors]
product: [HELM]
type: reference
last_reviewed: "2026-03-19"
owner: "@mindburn-labs/docs"
---

# HELM Architecture

> **Canonical** · v1.1 · Normative
>
> This document defines the architectural model of HELM. It describes
> trust boundaries, control loops, and data contracts.
>
> **Terminology**: follows the Unified Canonical Standard (UCS v1.2).

---

## 1. Design Thesis

HELM is a **fail-closed execution authority**. It sits between intent
and effect — every tool call, sandbox execution, and self-extension
passes through a governance boundary that produces signed, causal,
deterministic proof.

| Invariant         | Mechanism                                                  |
| :---------------- | :--------------------------------------------------------- |
| **Fail-closed**   | Unknown tools, unvalidated args, drifted outputs → `DENY`  |
| **Deterministic** | JCS (RFC 8785) canonicalization, SHA-256, Ed25519, Lamport |
| **Auditable**     | Every decision → ProofGraph node. EvidencePacks verifiable |

---

### 1.1 Execution Security Model

HELM enforces security through three independent, composable layers.
See [EXECUTION_SECURITY_MODEL.md](EXECUTION_SECURITY_MODEL.md) for the
full canonical reference.

| Layer | Property | Function |
| :---- | :------- | :------- |
| **A — Surface Containment** | Design-time | Reduces the **bounded surface** — the maximum set of reachable tools and destinations |
| **B — Dispatch Enforcement** | Dispatch-time | **Runtime execution enforcement** — per-call **execution admissibility** check at the PEP boundary |
| **C — Verifiable Receipts** | Post-execution | **Verifiable receipts** — cryptographic proof of every decision, offline-verifiable |

No single layer is sufficient. Layer A reduces blast radius, Layer B gates
each call, Layer C proves correct operation independently.

For OWASP MCP threat alignment, see [OWASP_MCP_THREAT_MAPPING.md](OWASP_MCP_THREAT_MAPPING.md).

---

## 2. Trust Boundaries

The **Trusted Computing Base (TCB)** is explicitly bounded. CI enforces
forbidden-import gates. The boundary covers: canonical data structures,
cryptographic operations, policy enforcement, gated execution, proof
graph construction, trust registry, sandbox isolation, receipt enforcement.

See [TCB_POLICY.md](TCB_POLICY.md) for the full package inventory.

---

## 3. Policy Precedence

    P0 Ceilings (hard limits — cannot be overridden)
         ↓
    P1 Policy Bundles (organizational governance)
         ↓
    P2 Overlays (runtime, per-session, per-agent)
         ↓
    CPI Verdict (Canonical Policy Index — deterministic validator)
         ↓
    PEP Execution (Guardian enforces, Executor runs)

**P0** — absolute ceilings. Budget maximums, forbidden effect types.
**P1** — policy bundles. Signed governance rules.
**P2** — runtime overlays. Session-scoped, can only narrow P1.
**CPI** — validates composed stack is internally consistent.
**PEP** — Guardian applies resolved policy, produces signed DecisionRecord.

---

### 2.1 Delegation Model

> *Added v1.3 — normative*

When a remote agent or bot acts on behalf of a human principal, a
**delegation session** mediates the authority transfer. HELM delegation
is designed to prevent the [confused deputy problem](https://en.wikipedia.org/wiki/Confused_deputy_problem):
the delegate can never exceed the delegator's own authority.

**Invariants:**

| Invariant | Mechanism |
| :-------- | :-------- |
| **Deny-all start** | New sessions have zero capabilities; each must be explicitly granted |
| **Subset-of-delegator** | Session capabilities ⊆ delegator's resolved policy stack |
| **Time-bounded** | Mandatory TTL; expired sessions produce `DELEGATION_INVALID` |
| **Anti-replay** | Session nonce tracked; replayed nonces produce `DELEGATION_INVALID` |
| **Verifier-bound** | Optional PKCE-style hash binding; verifier required at use time |
| **MFA-consent** | Sessions may require MFA at creation for high-risk delegation |

**Policy integration:**

Delegation sessions compile into **P2-equivalent narrowing overlays**.
They can only narrow P1 policy bundles — they can never expand authority
beyond what the delegator holds. The effective permission set is:

    Effective = P0 ∩ P1 ∩ DelegationSession.Capabilities

**ProofGraph representation:**

| Event | Node Kind | Payload |
| :---- | :-------- | :------ |
| Session creation | `ATTESTATION` | Signed `DelegationSession` |
| Identity binding (agent → delegator) | `TRUST_EVENT` | `{event: "DELEGATION_BIND", session_id, delegate, delegator}` |
| Session revocation / expiry | `TRUST_EVENT` | `{event: "DELEGATION_REVOKE", session_id, reason}` |

**Guardian enforcement:**

Delegation validation executes as **Gate 5** in the Guardian pre-PDP
gate chain (after threat scan, before effect construction). Invalid or
out-of-scope sessions produce canonical `DENY` verdicts with
`DELEGATION_INVALID` or `DELEGATION_SCOPE_VIOLATION` reason codes.

> **TCB impact**: delegation-aware principal evaluation touches
> truth-plane logic. This does _not_ weaken or fork TCB semantics —
> it extends the principal authorization path within the existing TCB
> boundary. See [TCB_POLICY.md](TCB_POLICY.md).

---

## 4. Verified Planning Loop (VPL)

The canonical execution protocol: propose → validate → verdict → execute → receipt → checkpoint.

    Request → API Layer → Guardian (PEP)
                              ├─ PDP   (CEL / PRG evaluation)
                              ├─ PRG   (Proof Requirement Graph)
                              ├─ Budget (ACID budget lock)
                              └─ Compliance
                              │
                         DENY → Signed DenialReceipt → ProofGraph → 403
                         ALLOW → AuthorizedExecutionIntent
                              │
                         SafeExecutor → Tool Driver → Canonicalize → Receipt
                              │
                         ProofGraph → Checkpoint (Proof Condensation)

### 4.1 Proof Condensation

Risk-tiered evidence routing reduces storage cost while preserving auditability.

| Risk Tier  | Retention                             | After Checkpoint                |
| :--------- | :------------------------------------ | :------------------------------ |
| High (T3+) | Full receipt chain, no condensation   | Anchored to transparency log   |
| Medium     | Full receipts + periodic checkpoints  | Condensed after window          |
| Low        | Condensed to Merkle inclusion proofs  | Individual receipts prunable    |

Condensation checkpoint: Merkle root over accumulated receipts. After
checkpoint, low-risk receipts can be replaced by inclusion proofs.

---

## 5. Core Data Contracts

- **DecisionRecord**: Verdict + ReasonCode + PolicyDecisionHash + Ed25519 signature + LamportClock
- **Effect**: ToolName + EffectType + InputHash + OutputHash
- **AuthorizedExecutionIntent**: DecisionID + Guardian signature + TTL
- **Receipt**: EffectHash + OutputHash + ArgsHash + PrevReceiptHash + LamportClock + Ed25519 signature
- **EvidencePack**: Receipts + MerkleRoot + ProofGraphHash + Ed25519 signature

---

## 6. External Interfaces

- **OpenAI-compatible proxy** — `POST /v1/chat/completions`
- **MCP gateway** — `GET /mcp/v1/capabilities`, `POST /mcp/v1/execute`
- **Governance REST API** — evidence export, budget status, authz check

---

## 7. Conformance Levels

| Level | Scope                                                                      |
| :---- | :------------------------------------------------------------------------- |
| L1    | TCB boundary, crypto signing, schema PEP, receipt chain, sandbox isolation |
| L2    | L1 + budget, approval ceremonies, evidence pack, replay, temporal          |
| L3    | L2 + HSM key management, bundle integrity, condensation checkpoints        |

---

## 8. Deployment Patterns

- **Sidecar proxy** — default, single `base_url` change
- **MCP server** — `helm mcp-server` for MCP-native clients
- **Gateway** — shared instance for multiple agents/services
- **In-process** — embedded as a Go library

---

## Research-Backed Extensions (April 2026)

The following subsystems extend the core architecture with capabilities grounded in peer-reviewed research (58 arXiv papers, 2025-2026).

### Cryptographic Identity & Trust
- **Hybrid Signing** (`crypto/hybrid_signer.go`): Every receipt signed with both Ed25519 (classical) and ML-DSA-65 (post-quantum). Per ePrint 2025/2025, hybrid mode provides transitional quantum safety.
- **W3C DID** (`identity/did/`): Agents are addressable via `did:key` identifiers (W3C DID Core 1.0). Per arXiv 2511.02841, DIDs with Verifiable Credentials are the emerging standard for agent identity.
- **Continuous Delegation** (`identity/continuous_delegation.go`): Time-bound, revocable, scope-narrowing delegation with cascade revocation. Per arXiv 2604.07695 (AITH protocol).
- **AIP Verification** (`mcp/aip.go`): Agent Identity Protocol verification for MCP delegation chains. Per arXiv 2603.24775.

### Threat Detection & Defense
- **Ensemble Scanner** (`threatscan/ensemble.go`): Multi-scanner voting with ANY/MAJORITY/UNANIMOUS strategies. Per arXiv 2509.14285, coordinated defense achieves 100% attack mitigation.
- **DDIPE Scanner** (`mcp/docscan.go`): Detects Document-Driven Implicit Payload Execution in MCP tool documentation. Per arXiv 2604.03081.
- **MCPTox Harness** (`mcp/mcptox_test.go`): Validates HELM blocks all MCPTox attack categories. Per arXiv 2508.14925 (o1-mini: 72.8% ASR unprotected).

### Memory Governance
- **Memory Integrity** (`kernel/memory_integrity.go`): SHA-256 hash-protected memory entries with tamper detection. Per arXiv 2603.20357.
- **Memory Trust Scoring** (`kernel/memory_trust.go`): Temporal decay + source trust + injection pattern detection. Per arXiv 2601.05504 (MINJA: 95% injection success without protection).

### Supply Chain Security
- **SkillFortify** (`pack/verify_capabilities.go`): Static analysis proving skills cannot exceed declared capabilities. Per arXiv 2603.00195 (CVE-2026-25253).
- **Provenance Verification** (`pack/provenance.go`): Cryptographic verification of pack publisher signatures. Per arXiv 2604.08407 (LiteLLM supply chain attack, March 2026).

### Evidence & Compliance
- **Constant-Size Summaries** (`evidencepack/summary.go`): O(1) evidence completeness proof. Per arXiv 2511.17118.
- **Cost Attribution** (`effects/types.go`): Per-agent, per-department cost breakdown in ProofGraph.
- **Cost Estimation** (`budget/estimate.go`): Pre-execution cost prediction from historical data.

### Policy Intelligence
- **Policy Suggestions** (`policy/suggest/`): Auto-generate policy rules from execution history. Per arXiv 2601.10440.
- **Static Verification** (`policy/verify/`): Detect circular dependencies, shadowed rules, escalation loops. Per arXiv 2512.09758.
- **Replay Comparison** (`replay/compare.go`): Compare governance decisions across sessions. Per arXiv 2601.00481.

### Federation
- **Federated Trust** (`mcp/trust.go`): Cross-organization reputation scoring with 0.7/0.3 local/federated blending. Per arXiv 2602.15055.
- **ZK Compliance Proofs** (`crypto/zkp/`): Interfaces for zero-knowledge governance verification. Per arXiv 2512.14737. Full circuit implementation planned Q3 2026.

---

## Normative References

| Document                                                         | Scope                              |
| :--------------------------------------------------------------- | :--------------------------------- |
| [EXECUTION_SECURITY_MODEL.md](EXECUTION_SECURITY_MODEL.md)       | Three-layer execution security model |
| [OWASP_MCP_THREAT_MAPPING.md](OWASP_MCP_THREAT_MAPPING.md)       | OWASP MCP threat alignment         |
| [CAPABILITY_MANIFESTS.md](CAPABILITY_MANIFESTS.md)               | Layer A configuration primitives   |
| [GOVERNANCE_SPEC.md](GOVERNANCE_SPEC.md)                         | PDP contracts, denial, jurisdiction |
| [SECURITY_MODEL.md](SECURITY_MODEL.md)                           | Execution pipeline, crypto, sandbox |
| [TCB_POLICY.md](TCB_POLICY.md)                                   | TCB boundary rules                 |
| [THREAT_MODEL.md](THREAT_MODEL.md)                               | Adversary classes                  |
| [CONFORMANCE.md](CONFORMANCE.md)                                 | Gate definitions, levels           |
| [OSS_SCOPE.md](OSS_SCOPE.md)                                     | Shipped vs. spec boundary          |

_Canonical revision: 2026-03-08 · HELM UCS v1.2_
