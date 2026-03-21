# Security Model

> **Canonical architecture**: see [ARCHITECTURE.md](ARCHITECTURE.md) for the
> system-level model (trust boundaries, VPL, Proof Condensation).

## Design Principle: Fail-Closed, Proof-First

HELM assumes every external input is adversarial. The kernel enforces a strict
policy enforcement point (PEP) at every execution boundary. If validation fails
at any stage, execution halts — there is no fallback path.

## Three-Layer Execution Security Model

This security model implements all three layers of HELM's canonical execution
security architecture. See [EXECUTION_SECURITY_MODEL.md](EXECUTION_SECURITY_MODEL.md)
for the full layer definitions.

| This Document Section | Layer |
| :--- | :--- |
| Sandbox Model (WASI) | **A — Surface Containment** |
| Execution Pipeline, Cryptographic Chain, Approval Ceremonies, Delegation | **B — Dispatch Enforcement** |
| EvidencePack | **C — Verifiable Receipts** |

## Execution Pipeline

The canonical execution protocol is the Verified Planning Loop (VPL) — see
[ARCHITECTURE.md §5](ARCHITECTURE.md#5-runtime-execution--verified-planning-loop-vpl).

```
Request → Guardian (policy) → PEP (schema + hash) → SafeExecutor → Driver
                                                         │
                                              ┌──────────▼──────────┐
                                              │  Output Validation  │
                                              │  (pinned schema)    │
                                              └──────────┬──────────┘
                                                         │
                                              ┌──────────▼──────────┐
                                              │  Sign Receipt       │
                                              │  (Ed25519)          │
                                              └──────────┬──────────┘
                                                         │
                                              ┌──────────▼──────────┐
                                              │  ProofGraph DAG     │
                                              │  (append-only)      │
                                              └─────────────────────┘
```

## Cryptographic Chain

Every execution produces the following cryptographic artifacts:

1. **ArgsHash** — SHA-256 of JCS-canonicalized tool arguments
2. **OutputHash** — SHA-256 of validated connector output
3. **Receipt** — signed record binding: `ReceiptID:DecisionID:EffectID:Status:OutputHash:PrevHash:LamportClock:ArgsHash`
4. **PrevHash** — signature of the previous receipt (causal link)

This chain is append-only and verifiable offline.

## Trusted Computing Base (TCB)

The TCB is explicitly bounded to 8 packages. For the full inventory and
expansion criteria, see [TCB_POLICY.md](TCB_POLICY.md).

| Package           | Responsibility                                                |
| ----------------- | ------------------------------------------------------------- |
| `contracts`       | Canonical data structures (Decision, Effect, Receipt, Intent) |
| `crypto`          | Ed25519 signing, verification, JCS canonicalization           |
| `guardian`        | Policy enforcement (PEP, PRG, compliance)                     |
| `executor`        | SafeExecutor — gated execution, idempotency                   |
| `proofgraph`      | Append-only DAG, AIGP anchors                                 |
| `trust`           | Event-sourced key registry, TUF, Rekor, SLSA                  |
| `runtime/sandbox` | WASI isolation: gas, time, memory caps                        |
| `receipts`        | Receipt policy enforcement (fail-closed)                      |

**TCB expansion requires**: deterministic behavior, no external I/O, no
reflection, >80% test coverage, maintainer review (see [TCB_POLICY.md](TCB_POLICY.md)).

## Sandbox Model (WASI)

Untrusted code executes in a WASI sandbox with:

- **No filesystem access** (deny-by-default)
- **No network access** (deny-by-default)
- **Gas metering** — hard budget per invocation
- **Wall-clock timeout** — configurable per tool
- **Memory cap** — WASM linear memory bounded
- **Deterministic traps** — budget exhaustion produces stable error codes

## Approval Ceremonies

High-risk operations require human approval via the approval ceremony,
which binds cryptographic hashes — see
[ARCHITECTURE.md §3](ARCHITECTURE.md#3-policy-precedence):

1. `policy_bundle_hash` — SHA-256 of active policy bundle set
2. `p0_ceiling_hash` — SHA-256 of active P0 ceiling set
3. `intent_hash` — SHA-256 of the proposed execution intent
4. `approver_signature` — Ed25519 signature from authorized approver

The ceremony supports timelock, quorum, rate limits, and emergency override.

## Delegation Sessions

> *Added v1.3 — normative*

When an agent acts on behalf of a human (the confused deputy scenario),
HELM requires a **delegation session** that cryptographically binds the
delegate's authority to a subset of the delegator's own privileges.

**Key distinction**: identity (who is this agent?) vs. authority (what
can this agent do, under which exact constraints?). Upstream identity
providers (Teleport, SPIFFE, OIDC) answer the first question. HELM's
delegation session answers the second — and enforces it at the PEP.

**Threat mitigation:**

| Threat | Mitigation |
| :----- | :--------- |
| **Confused deputy** (Hardy 1988) | Deny-all start; explicit capability grants only |
| **Privilege escalation** | Session capabilities ⊆ delegator's policy stack |
| **Session hijack** | PKCE verifier binding + short TTL |
| **Replay** | One-time nonce per session, tracked by DelegationStore |
| **Unauthorized creation** | Optional MFA gate at session creation |

**PEP integration:**

Delegation validation runs as Guardian Gate 5 — inside the existing
gate chain, not parallel to it. This means:

1. Frozen system (Gate 0) still overrides delegation
2. Context mismatch (Gate 1) still overrides delegation
3. Identity isolation (Gate 2) still checked before delegation
4. Egress control (Gate 3) still enforced independently
5. Threat scan (Gate 4) still blocks tainted input
6. **Delegation (Gate 5)** — validate session, intersect scope
7. Effect construction + PRG/PDP evaluation proceed as normal

This ordering ensures delegation never bypasses any existing security
gate. See [ARCHITECTURE.md §2.1](ARCHITECTURE.md#21-delegation-model).

## EvidencePack

Every session can be exported as a deterministic `.tar` containing:

- Retained receipts (signed) + Merkle inclusion proofs for condensed entries
- ProofGraph DAG state
- Trust registry snapshot
- Schema versions used
- Replay script

The archive is byte-identical for identical content (sorted paths, epoch mtime,
root uid/gid, fixed permissions). Low-risk receipts may be replaced by inclusion
proofs after checkpoint — see [ARCHITECTURE.md §5.2](ARCHITECTURE.md#52-proof-condensation).
