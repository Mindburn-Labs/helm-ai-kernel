# HELM Governance Protocol Specification

**Version**: 1.0.0  
**Status**: Draft  
**Last Updated**: 2026-03-22

## 1. Overview

The HELM Governance Protocol defines the wire format and semantics for AI governance operations. It is designed to be:

- **Deterministic**: Same inputs always produce same outputs
- **Fail-closed**: Unknown states default to DENY
- **Verifiable**: Every decision produces an auditable receipt
- **Bounded**: All operations complete within finite compute and time

This specification is language-agnostic and implementation-neutral.

## 2. Envelope Format

### 2.1 Autonomy Envelope

The Autonomy Envelope is the fundamental governance boundary for an AI agent session.

```
┌──────────────────────────────────────────────┐
│ Autonomy Envelope                            │
│                                              │
│  envelope_id:     string (UUID)              │
│  version:         semver                     │
│  valid_from:      RFC3339 timestamp          │
│  valid_until:     RFC3339 timestamp          │
│  tenant_id:       string                     │
│                                              │
│  ┌──────────────────────────────────────┐    │
│  │ Jurisdiction Scope                   │    │
│  │  allowed_jurisdictions: string[]     │    │
│  │  prohibited_jurisdictions: string[]  │    │
│  │  regulatory_mode: STRICT|PERMISSIVE  │    │
│  │  data_residency_regions: string[]    │    │
│  └──────────────────────────────────────┘    │
│                                              │
│  ┌──────────────────────────────────────┐    │
│  │ Effect Allowlist                     │    │
│  │  E0: read-only (unrestricted)        │    │
│  │  E1: append-only (capped)            │    │
│  │  E2: mutate-own (capped)             │    │
│  │  E3: mutate-shared (approval above N)│    │
│  │  E4: irreversible (denied by default)│    │
│  └──────────────────────────────────────┘    │
│                                              │
│  ┌──────────────────────────────────────┐    │
│  │ Budgets                              │    │
│  │  cost_ceiling_cents: int64           │    │
│  │  time_ceiling_seconds: int64         │    │
│  │  tool_call_cap: int64                │    │
│  │  blast_radius: RECORD|DATASET|SYSTEM │    │
│  └──────────────────────────────────────┘    │
│                                              │
│  ┌──────────────────────────────────────┐    │
│  │ Attestation                          │    │
│  │  content_hash: sha256:<hex>          │    │
│  │  signer_id: string                   │    │
│  │  algorithm: ed25519|ecdsa-p256       │    │
│  │  signature: base64                   │    │
│  └──────────────────────────────────────┘    │
└──────────────────────────────────────────────┘
```

### 2.2 A2A Envelope

Agent-to-Agent envelopes wrap inter-agent negotiation:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `envelope_id` | string | ✓ | Unique exchange identifier |
| `schema_version` | `{major, minor, patch}` | ✓ | Protocol version |
| `origin_agent_id` | string | ✓ | Initiating agent |
| `target_agent_id` | string | ✓ | Receiving agent |
| `required_features` | Feature[] | | Features origin requires |
| `offered_features` | Feature[] | | Features origin supports |
| `payload_hash` | string | ✓ | SHA-256 of payload |
| `signature` | Signature | ✓ | Cryptographic signature |
| `expires_at` | RFC3339 | | Expiration timestamp |

## 3. Verdict Semantics

Every governance decision produces exactly one verdict:

| Verdict | Semantics |
|---------|-----------|
| `ALLOW` | Effect is permitted within current envelope bounds |
| `DENY` | Effect is rejected; a denial receipt is emitted |
| `ESCALATE` | Effect requires human approval (quorum-based) |

Verdicts are **immutable** once emitted. There is no `ALLOW_CONDITIONAL` or `MAYBE`.

## 4. Reason Codes

Reason codes are deterministic identifiers attached to every verdict:

| Code | Verdict | Description |
|------|---------|-------------|
| `EFFECT_CLASS_DENIED` | DENY | Effect class not in envelope allowlist |
| `JURISDICTION_DENIED` | DENY | Jurisdiction prohibited or not in allowed list |
| `COST_CEILING_EXCEEDED` | DENY | Cumulative cost would exceed budget |
| `TIME_CEILING_EXCEEDED` | DENY | Time budget exhausted |
| `TOOL_CALL_CAP_EXCEEDED` | DENY | Tool call count exceeded |
| `BLAST_RADIUS_EXCEEDED` | DENY | Operation scope exceeds envelope blast radius |
| `DATA_CLASSIFICATION_EXCEEDED` | DENY | Data sensitivity exceeds envelope max |
| `ENVELOPE_EXPIRED` | DENY | Envelope validity period ended |
| `NO_ENVELOPE` | DENY | No active envelope bound (fail-closed) |
| `HASH_MISMATCH` | DENY | Content hash verification failed |
| `ESCALATION_REQUIRED` | ESCALATE | Effect count exceeds approval threshold |
| `POLICY_VIOLATION` | DENY | CEL policy rule evaluated to false |
| `VERSION_INCOMPATIBLE` | DENY | A2A protocol version mismatch |
| `FEATURE_MISSING` | DENY | Required A2A feature not available |
| `SIGNATURE_INVALID` | DENY | Envelope signature verification failed |

## 5. Receipt Format

Every verdict produces a receipt that is appended to the ProofGraph:

```json
{
  "receipt_id": "rcpt-<uuid>",
  "verdict": "ALLOW|DENY|ESCALATE",
  "reason_code": "<REASON_CODE>",
  "effect_class": "E0|E1|E2|E3|E4",
  "tool_name": "string",
  "envelope_id": "string",
  "policy_ref": "string",
  "lamport": 42,
  "prev_hash": "sha256:<hex>",
  "content_hash": "sha256:<hex>",
  "timestamp": "2026-03-22T16:00:00Z"
}
```

Receipts form a hash chain: each receipt's `prev_hash` references the prior receipt's `content_hash`. This produces a tamper-evident, verifiable audit trail.

## 6. ProofGraph DAG

The ProofGraph is a directed acyclic graph where:
- **Nodes** are receipts
- **Edges** are hash-chain links (`prev_hash → content_hash`)
- **Lamport** counters provide causal ordering

### 6.1 Condensation

For high-volume systems, receipts can be condensed into Merkle checkpoints:

```
Checkpoint:
  checkpoint_id: string
  merkle_root: sha256:<hex>
  start_lamport: uint64
  end_lamport: uint64
  receipt_count: int
  prev_checkpoint_id: string
```

**Risk-tier routing**: Receipts with risk tier T3+ (high-risk) are never condensed and are always individually preserved.

## 7. Conformance Levels

| Level | Name | Requirements |
|-------|------|-------------|
| L1 | Structural | Valid types, deterministic hashing, receipt chain |
| L2 | Execution | All L1 + governance verdicts, budget enforcement, drift detection |
| L3 | Adversarial | All L2 + HSM key ceremony (G13), bundle integrity (G14), proof condensation (G15) |

Conformance is verified by running the HELM conformance suite against an implementation.

## 8. Transport

This protocol is transport-agnostic. Reference transports:
- **HTTP/JSON**: `POST /v1/decide` with JSON request/response
- **gRPC**: Protobuf-encoded using schemas in `protocols/proto/`
- **In-process**: Direct function call (Go, Rust, etc.)

## 9. Security Considerations

- All envelope content hashes use SHA-256 with domain separation prefixes
- Key rotation follows ceremony-based HSM model
- Emergency revocation propagates within 1 lamport tick
- Policy bundles are content-addressed and signed
- A2A negotiation is fail-closed: any incompatibility → DENY
