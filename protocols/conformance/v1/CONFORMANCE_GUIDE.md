# HELM Conformance Guide

> How to prove a HELM-compatible implementation is conformant.

## 1. Conformance Levels

| Level                   | Requirement                                      |
| ----------------------- | ------------------------------------------------ |
| **Level 1: Core**       | Pass all ALLOW/DENY/ESCALATE verdict vectors     |
| **Level 2: Receipts**   | Generate receipts matching receipt invariants    |
| **Level 3: ProofGraph** | Maintain hash chain with monotonic Lamport clock |
| **Level 4: Full**       | All above + fail-closed behavior + reason codes  |

## 2. Test Vector Structure

Test vectors are in `protocols/conformance/v1/test-vectors.json`.

Each vector specifies:

- `input`: Effect, principal, and context to submit
- `expected`: Verdict, reason code, receipt presence, intent presence
- `pdp_behavior` (optional): How the PDP should respond for this test

## 3. Running Conformance Tests

### Against the Go Reference

```bash
cd core && go test ./pkg/conform/... -tags conformance
```

### Against an External Implementation

1. Start your PDP/EffectBoundary server
2. Run the conformance runner:

```bash
helm-ai-kernel conform run \
  --vectors protocols/conformance/v1/test-vectors.json \
  --endpoint http://your-server:4001 \
  --level 4
```

### Against a Language SDK

Each SDK ships with a conformance test harness:

```bash
# Python
cd sdk/python && pytest tests/conformance/

# TypeScript
cd sdk/ts && npm run test:conformance

# Java
cd sdk/java && mvn test -Pconformance
```

## 4. Receipt Invariants

Every receipt produced by a conformant implementation MUST satisfy:

1. `receipt_id` is non-empty and unique
2. `verdict` matches the returned verdict
3. `timestamp` is monotonically increasing within a session
4. `signature` is verifiable with the signer's public key
5. `payload_hash` is SHA-256 of the canonical (JCS) JSON payload
6. `reason_code` is a registered code from `reason-codes-v1.json`
7. `lamport` is strictly increasing within a ProofGraph

## 5. Hash Chain Invariants

1. Each node hash includes the hashes of parent nodes
2. Lamport values are strictly increasing
3. Removing any node breaks chain verification
4. Node hashes are computed using JCS (JSON Canonicalization Scheme)

## 6. Fail-Closed Invariant

If the PDP is unreachable:

- The EffectBoundary MUST return `DENY`
- Reason code MUST be `PDP_ERROR`
- A receipt MUST still be generated

This is the **non-negotiable kernel invariant**.

## 7. Certification Badge

Implementations passing Level 4 conformance may display:

```
[![HELM Conformant](https://helm.mindburn.run/badges/conformant-v1.svg)](https://helm.mindburn.run/conformance)
```

## 8. Compatibility Tiers

Beyond conformance levels, HELM defines **compatibility tiers** for ecosystem
participants (runtimes, frameworks, clients):

| Tier           | Requirements                                                                     | Verification                                                                       |
| -------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Compatible** | Passes core verdict vectors (Level 1–2). Self-certified.                         | Self-reported; not independently verified.                                         |
| **Verified**   | Passes all Level 4 conformance vectors against published fixtures. CI-exercised. | Verified via published CI workflow. Artifacts published to compatibility registry. |
| **Sovereign**  | Verified + full TLA+ invariant alignment + independent verifier passes.          | Third-party audit confirms invariant coverage. Eligible for HELM Sovereign badge.  |

### 8.1 Required Fixture Sets by Tier

| Fixture Set                     | Compatible | Verified | Sovereign |
| ------------------------------- | ---------- | -------- | --------- |
| `vectors` (ALLOW/DENY/ESCALATE) | ✅         | ✅       | ✅        |
| `receipt_invariants`            | —          | ✅       | ✅        |
| `hash_chain_vectors`            | —          | ✅       | ✅        |
| `golden_receipts`               | —          | ✅       | ✅        |
| `lifecycle_fixtures`            | —          | ✅       | ✅        |
| `jurisdiction_fixtures`         | —          | —        | ✅        |
| `evidence_bundle_fixture`       | —          | —        | ✅        |

### 8.2 Claiming a Tier

1. Run conformance vectors against your implementation.
2. Publish results to `compatibility-registry.json` (or submit PR).
3. CI artifact must include: tier, date, HELM spec version, vector version, pass/fail summary.

## 9. Lifecycle Fixtures

Conformant implementations MUST handle the effect lifecycle state machine:

- **Happy path**: SUBMITTED → APPROVED → EXECUTING → COMPLETED
- **Deny path**: SUBMITTED → DENIED
- **Escalation path**: SUBMITTED → ESCALATED → APPROVED or DENIED

See `lifecycle_fixtures` in `test-vectors.json` for exact transition definitions.
