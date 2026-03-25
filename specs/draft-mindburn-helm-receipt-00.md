---
title: "HELM Governance Receipt Format"
abbrev: "HELM-Receipt"
docname: draft-mindburn-helm-receipt-00
category: std
ipr: trust200902

author:
  - fullname: Ivan Kirilov
    organization: Mindburn Labs
    email: ivan@mindburn.org

normative:
  RFC8785: JCS
  RFC8032: EdDSA
  RFC3161: TSA
  RFC6962: CT

informative:
  SIGSTORE: Sigstore

--- abstract

This document defines the HELM Governance Receipt, a signed data
structure that provides cryptographic proof of a governance decision
made during AI agent execution. Receipts form a causal chain via
Lamport clocks and content-addressed hashes, enabling offline
verification and tamper detection.

--- middle

# Introduction

As AI agents perform increasingly consequential actions, verifiable
governance becomes essential. The HELM Governance Receipt provides a
standardized format for recording governance decisions with:

- **Cryptographic non-repudiation** via Ed25519 signatures {{RFC8032}}
- **Causal ordering** via Lamport logical clocks
- **Content-addressed chaining** via SHA-256 hash links
- **Deterministic canonicalization** via JCS {{RFC8785}}

Each receipt is a self-contained proof that a specific action was
evaluated against a specific policy and received a specific verdict.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Receipt Structure

A HELM Governance Receipt is a JSON object with the following fields:

~~~ json
{
  "receipt_id": "rcpt-2026-001",
  "decision_id": "dec-001",
  "effect_id": "write_file",
  "status": "ALLOW",
  "timestamp": "2026-03-23T14:30:00Z",
  "executor_id": "agent-001",
  "signature": "<hex-ed25519>",
  "prev_hash": "sha256:<hex>",
  "lamport_clock": 42,
  "args_hash": "sha256:<hex>",
  "merkle_root": "sha256:<hex>"
}
~~~

## Required Fields

receipt_id:
: A globally unique identifier for this receipt (REQUIRED).

decision_id:
: Identifier of the governance decision that authorized this action (REQUIRED).

effect_id:
: The tool or effect that was evaluated (REQUIRED).

status:
: The governance verdict: "ALLOW", "DENY", or "ERROR" (REQUIRED).

timestamp:
: RFC 3339 timestamp of the decision (REQUIRED).

signature:
: Ed25519 signature ({{RFC8032}}) over the JCS-canonicalized receipt,
  hex-encoded (REQUIRED).

prev_hash:
: SHA-256 hash of the immediately preceding receipt's signature in
  the causal chain: "sha256:" || hex(SHA-256(prev_signature)) (REQUIRED).
  For the genesis receipt, this MUST be the string
  "sha256:genesis".

lamport_clock:
: Monotonically increasing logical clock per session. Each receipt's
  Lamport clock MUST be strictly greater than its predecessor's (REQUIRED).

## Optional Fields

executor_id:
: Identifier of the executing agent or node (OPTIONAL).

args_hash:
: SHA-256 hash of the JCS-canonicalized tool arguments. This enables
  verification of what arguments were authorized without revealing
  the arguments themselves (OPTIONAL).

merkle_root:
: When present, the SHA-256 Merkle root of the receipt batch that
  includes this receipt (OPTIONAL).

blob_hash:
: Content-addressed reference to the input snapshot in CAS (OPTIONAL).

output_hash:
: Content-addressed reference to the tool output in CAS (OPTIONAL).

metadata:
: Arbitrary key-value pairs for domain-specific context (OPTIONAL).

# Causal Chain

Receipts form a causal chain through two mechanisms:

1. **prev_hash linking**: Each receipt contains the SHA-256 hash of
   the previous receipt's signature, creating a hash chain.

2. **Lamport clocks**: Each receipt carries a monotonically increasing
   logical clock scoped to a session. Clock values MUST be strictly
   increasing.

Together, these provide:
- Tamper detection: modifying any receipt breaks the hash chain
- Gap detection: missing Lamport values indicate dropped receipts
- Causal ordering: receipts can be totally ordered within a session

# Signature

The receipt signature is computed as follows:

1. Construct the canonical form by JCS-serializing ({{RFC8785}}) all
   receipt fields except `signature` and `merkle_root`.
2. Compute SHA-256 over the canonical bytes.
3. Sign the digest with Ed25519 ({{RFC8032}}).
4. Hex-encode the 64-byte signature.

Verification:
1. Re-derive the canonical form.
2. Verify the Ed25519 signature against the signer's public key.

# Merkle Rollup

Receipts MAY be batched into Merkle trees for transparency log
anchoring:

1. Leaves are domain-separated: "helm:evidence:leaf:v1\0" || receipt_id || "\0" || canonical_json
2. Internal nodes are domain-separated: "helm:evidence:node:v1\0" || left_hash || right_hash
3. The Merkle root is the SHA-256 of the final node.

The resulting root MAY be anchored to:
- Sigstore Rekor {{SIGSTORE}} for transparency
- An RFC 3161 TSA {{RFC3161}} for timestamping
- Certificate Transparency logs {{RFC6962}}

# Verification

A receipt chain is verified by:

1. For each receipt, verify the Ed25519 signature.
2. For each non-genesis receipt, verify prev_hash matches
   SHA-256 of the predecessor's signature.
3. Verify Lamport clocks are strictly monotonic.
4. If merkle_root is present, verify the receipt is included
   in the Merkle tree via an inclusion proof.

# Security Considerations

- **Key management**: The signing key MUST be stored securely.
  Compromise of the signing key enables forged receipts.
- **Clock manipulation**: Lamport clocks provide logical ordering
  only. For wall-clock accountability, combine with RFC 3161
  timestamps.
- **Replay attacks**: Receipt IDs MUST be globally unique to prevent
  replay of valid receipts.
- **Fail-closed semantics**: The absence of a receipt for an action
  implies the action was denied (fail-closed). Systems MUST NOT
  rely on receipt presence for deny verification.

# IANA Considerations

This document has no IANA actions.

--- back

# Appendix A: Example Receipt Chain

~~~ json
[
  {
    "receipt_id": "rcpt-001",
    "decision_id": "dec-001",
    "effect_id": "read_file",
    "status": "ALLOW",
    "timestamp": "2026-03-23T14:30:00Z",
    "signature": "4a8f2c...",
    "prev_hash": "sha256:genesis",
    "lamport_clock": 1
  },
  {
    "receipt_id": "rcpt-002",
    "decision_id": "dec-002",
    "effect_id": "write_file",
    "status": "DENY",
    "timestamp": "2026-03-23T14:30:01Z",
    "signature": "7b3d1e...",
    "prev_hash": "sha256:e7b3a1...",
    "lamport_clock": 2
  }
]
~~~
