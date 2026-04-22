---
title: "HELM Receipt Format Specification"
status: final
version: "1.0.0"
created: 2026-02-25
finalized: 2026-03-06
authors:
  - HELM Core Team
---

# RFC: HELM Receipt Format v1.0

## Abstract

This document specifies the canonical format for HELM governance receipts.
A receipt is a cryptographically signed, content-addressed record that
attests to a governance decision and its execution outcome.

## Status

Final — Normative Standard

## 1. Introduction

HELM is an AI governance kernel that produces an immutable audit trail
of every governance decision and tool execution. The receipt is the
fundamental unit of this audit trail.

### 1.1 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 2. Receipt Structure

A receipt MUST be a JSON object with the following fields:

```json
{
  "receipt_version": "1.0",
  "receipt_id": "<content-addressed SHA-256 hash>",
  "decision_id": "<decision identifier>",
  "effect_id": "<effect identifier>",
  "verdict": "ALLOW | DENY | ESCALATE",
  "principal": "<principal identifier>",
  "tool": "<tool identifier>",
  "action": "<action description>",
  "timestamp": "<RFC 3339 timestamp>",
  "lamport": <monotonic Lamport clock>,
  "proofgraph_node": "<ProofGraph node hash>",
  "signature": "<Ed25519 signature, base64>",
  "signer_key_id": "<public key identifier>",
  "payload_hash": "<SHA-256 of the execution payload>",
  "metadata": { ... }
}
```

### 2.1 Receipt ID

The `receipt_id` MUST be computed as:

```
receipt_id = SHA-256(canonical_json(receipt_without_id))
```

where `canonical_json` produces deterministic JSON with sorted keys.

### 2.2 Verdict

The `verdict` field MUST be one of:

- `ALLOW` — The decision was permitted.
- `DENY` — The decision was denied.
- `ESCALATE` — The decision requires human review.

### 2.3 Signature

The `signature` field MUST be an Ed25519 signature over the `receipt_id`.
The `signer_key_id` MUST reference a key published in the trust root.

### 2.5 Reason Code

When `verdict` is `DENY` or `ESCALATE`, a `reason_code` field SHOULD be
present. Valid reason codes form the following normative registry:

| Code                     | Category     | Description                                       |
| ------------------------ | ------------ | ------------------------------------------------- |
| `POLICY_VIOLATION`       | Policy       | General policy rule violation                     |
| `NO_POLICY_DEFINED`      | Policy       | No policy exists for the requested action         |
| `PRG_EVALUATION_ERROR`   | Policy       | Error evaluating the Proof Requirement Graph      |
| `MISSING_REQUIREMENT`    | Policy       | Required evidence or condition not met            |
| `PDP_DENY`               | PDP          | External policy decision point denied the request |
| `PDP_ERROR`              | PDP          | External PDP returned an error (fail-closed)      |
| `BUDGET_EXCEEDED`        | Resource     | Financial or rate budget exhausted                |
| `BUDGET_ERROR`           | Resource     | Error checking budget (fail-closed)               |
| `ENVELOPE_INVALID`       | Schema       | Effect envelope failed structural validation      |
| `SCHEMA_VIOLATION`       | Schema       | Payload violates declared schema                  |
| `TEMPORAL_INTERVENTION`  | Temporal     | Temporal guardian triggered intervention          |
| `TEMPORAL_THROTTLE`      | Temporal     | Temporal guardian applied throttling              |
| `SANDBOX_VIOLATION`      | Security     | Sandbox security boundary violated                |
| `PROVENANCE_FAILURE`     | Security     | Artifact provenance verification failed           |
| `VERIFICATION_FAILURE`   | Security     | Cryptographic verification failed                 |
| `TENANT_ISOLATION`       | Tenancy      | Multi-tenant isolation boundary violated          |
| `JURISDICTION_VIOLATION` | Jurisdiction | Jurisdictional constraint not met                 |

### 2.4 Lamport Clock

The `lamport` field MUST be a monotonically increasing unsigned integer.
Each receipt MUST have a `lamport` value strictly greater than all
previously issued receipts from the same HELM kernel instance.

## 3. ProofGraph Integration

Each receipt MUST correspond to exactly one node in the ProofGraph.
The `proofgraph_node` field contains the hash of the ProofGraph node.

ProofGraph nodes form a hash-chained DAG where each node references
its parent nodes, creating a tamper-evident audit trail.

## 4. Serialization

### 4.1 Canonical JSON

For content addressing, receipts MUST be serialized using canonical
JSON (RFC 8785 — JSON Canonicalization Scheme).

### 4.2 Content Addressing

All content-addressed identifiers in HELM use SHA-256:

```
id = hex(SHA-256(canonical_bytes))
```

## 5. Verification

To verify a receipt:

1. Recompute `receipt_id` from the receipt fields.
2. Verify `receipt_id` matches the declared value.
3. Verify the Ed25519 `signature` over `receipt_id` using the public key identified by `signer_key_id`.
4. Verify the `lamport` clock is within expected bounds.
5. Verify the `proofgraph_node` exists in the ProofGraph.

## 6. Security Considerations

- **Fail-Closed**: Without a valid receipt, the system MUST NOT permit effect execution.
- **Non-Repudiation**: Receipts are cryptographically signed and content-addressed.
- **Tamper Evidence**: ProofGraph hash chains detect any modification.
- **Forward Secrecy**: Receipts do not contain session keys or ephemeral material.

## 7. IANA Considerations

This document has no IANA actions.

## 8. References

- RFC 2119 — Key Words for use in RFCs
- RFC 3339 — Date and Time on the Internet
- RFC 8785 — JSON Canonicalization Scheme
- AIGP Four Tests Standard (4TS) v1.0
- HELM Unified Canonical Standard (UCS) v1.2
