---
title: "Conformance Levels"
description: "L1, L2, and L3 conformance gates — what each level guarantees and how to test."
category: overview
order: 4
status: Canonical
audience: [Users, Developers, Auditors]
product: [HELM]
type: reference
last_reviewed: "2026-03-15"
owner: "@mindburn-labs/docs"
---

# HELM Conformance

> **Canonical architecture**: see [ARCHITECTURE.md §8](ARCHITECTURE.md#8-conformance-levels)
> for normative level definitions.

## Levels

| Level  | Meaning                                                                                                                                                       | Gates     |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| **L1** | Core kernel correctness: JCS canonicalization, PEP boundary, Ed25519 signatures, Lamport clock ordering, ProofGraph DAG integrity                             | 6         |
| **L2** | Full operational correctness: L1 + WASI sandbox bounds, approval ceremonies, EvidencePack determinism, offline replay, output drift detection, trust rotation | 12        |
| **L3** | Enterprise correctness: L2 + HSM key management (G13), policy bundle integrity (G14), proof condensation (G15)                                                | Shipped |

## Running Conformance

```bash
# Build
make build

# Run L1
./bin/helm conform --level L1 --json

# Run L2 (includes all L1 gates)
./bin/helm conform --level L2 --json
```

## Expected Output (L2)

```json
{
  "run_id": "conform-...",
  "profile": "CORE",
  "pass": true,
  "timestamp": "2026-03-22T...",
  "duration": "...",
  "gate_results": [
    {"gate_id": "G0", "pass": true, "reasons": []},
    {"gate_id": "G1", "pass": true, "reasons": []},
    {"gate_id": "G2", "pass": true, "reasons": []}
  ]
}
```

## Gate Details

1. **JCS Canonicalization** — RFC 8785 deterministic JSON serialization
2. **PEP Boundary** — Schema validation on both input and output
3. **WASI Sandbox** — Gas, time, and memory bounds enforced
4. **Approval Ceremony** — Timelock + 4-hash challenge/response with Ed25519
5. **ProofGraph DAG** — Append-only, Lamport-ordered, hash-chained
6. **Trust Registry** — Event-sourced key lifecycle
7. **Evidence Pack** — Deterministic export (same content → same hash)
8. **Offline Replay** — Replay from genesis without network
9. **Output Drift** — SHA-256 output hash mismatch detection
10. **Idempotency** — Receipt-based duplicate rejection
11. **Island Mode** — Build and verify without network
12. **Conformance Gates** — Self-test harness

## L3 Gates (Shipped)

L3 conformance gates extend L2 with enterprise requirements.
These gates are structurally implemented but not yet adversarially tested.

| Gate    | Requirement                                                               |
| ------- | ------------------------------------------------------------------------- |
| **G13** | HSM key management — hardware-backed signing with ceremony-based rotation |
| **G14** | Policy bundle integrity — signed bundles with content-addressed loading   |
| **G15** | Proof condensation — Merkle checkpoints for long-running sessions         |

### Research-Backed Verification (April 2026)

In addition to the standard L1/L2/L3 gates, HELM now includes:
- **MCPTox benchmark validation** — all 6 MCPTox attack categories blocked (arXiv 2508.14925)
- **SkillFortify verification** — static capability analysis at pack install time
- **Provenance verification** — cryptographic publisher signature checking
- **Static policy verification** — circular dependency and shadowed rule detection
- **Evidence summary verification** — constant-size integrity proofs

## CI Integration

Conformance runs as a CI gate on every push to `main`. See `.github/workflows/helm_core_gates.yml` → `conformance-gate` job.
