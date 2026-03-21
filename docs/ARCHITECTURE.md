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
