---
title: "HELM Receipt Transparency Log Specification"
status: draft
version: "1.0.0"
created: 2026-06-10
authors:
  - HELM Core Team
---

# RFC: HELM Receipt Transparency Log v1.0

## Abstract

This document specifies the HELM receipt transparency log: an
RFC 6962-style append-only Merkle tree over receipt hashes, with signed
tree heads (STH), inclusion proofs, and consistency proofs. A receipt
signature proves *who* issued a receipt; the transparency log proves
*no contradictory receipt exists*. Without anti-equivocation, an
operator could issue two receipts for the same effect and show each
party a different one. Certificate Transparency (RFC 6962 / RFC 9162)
is the model.

## Status

Draft — v1 ships the local log primitive, proofs, and CLI. The hosted
public log, monitors, and gossip network are explicitly out of scope
(commercial certification-authority surface).

## 1. Introduction

### 1.1 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

### 1.2 Reference Implementation

`core/pkg/translog` implements this specification. The CLI surface is
`helm-ai-kernel log {append|sth|prove|verify-inclusion|verify-consistency}`.

## 2. Merkle Tree Construction

The log is an append-only binary Merkle tree over leaf inputs, hashed
with SHA-256 exactly as in RFC 6962 section 2.1:

```
leaf hash  = SHA-256(0x00 || leaf input)
node hash  = SHA-256(0x01 || left || right)
MTH({})    = SHA-256()   (empty string)
```

For n > 1 leaves, `MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`
where k is the largest power of two strictly less than n. The 0x00/0x01
domain separation prevents second-preimage attacks between leaves and
interior nodes.

### 2.1 Leaf Input

The leaf input for the receipt transparency log MUST be the raw bytes
of the receipt hash (the SHA-256 content address of the canonical
receipt as defined in `receipt-format-v1.md`). Verifiers recompute the
receipt hash from the canonical receipt and check inclusion of
`SHA-256(0x00 || receipt_hash_bytes)`.

### 2.2 Append-Only Persistence

Implementations MUST persist leaf hashes in append-only order. The
reference implementation journals one lowercase hex leaf hash per line
in `<data-dir>/translog/leaves`, fsynced per append. An append that
fails to persist MUST NOT advance the tree (fail-closed).

## 3. Signed Tree Head (STH)

An STH is an exportable checkpoint of the log at a given size, suitable
for cross-publication (EvidencePacks, Console, third-party witnesses).

```json
{
  "tree_size": 8,
  "root_hash": "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
  "timestamp": "2026-06-10T00:00:00Z",
  "log_id": "9b1c98c145e32a1f739ba0c1e4b7a26e92debc5db1b3a52aa21cef4b0c1f8a13",
  "public_key": "<hex Ed25519 public key>",
  "signature": "<hex Ed25519 signature>"
}
```

- `tree_size` — number of leaves covered by this head.
- `root_hash` — lowercase hex `MTH(D[tree_size])`.
- `timestamp` — RFC 3339 UTC time the checkpoint was produced.
- `log_id` — lowercase hex SHA-256 of the log's raw public key bytes
  (mirroring the RFC 6962 log ID construction).
- `signature` — kernel keyring signature (Ed25519) over the signing
  payload defined below.

### 3.1 Canonical Signing Payload (JCS)

The signature MUST cover the JCS (RFC 8785) canonical JSON serialization
of exactly these four fields:

```json
{"log_id":"…","root_hash":"…","timestamp":"…","tree_size":8}
```

JCS sorts keys lexicographically, forbids insignificant whitespace, and
disables HTML escaping, so any implementation reproduces byte-identical
signed payloads. `public_key` and `signature` are excluded from the
payload.

## 4. Proofs

Hashes in proofs are lowercase hex SHA-256. Proof generation and
verification MUST be pure, deterministic functions of their inputs.

### 4.1 Inclusion Proof

The audit path `PATH(m, D[n])` per RFC 6962 section 2.1.1:

```json
{
  "leaf_index": 3,
  "tree_size": 8,
  "leaf_hash": "<hex>",
  "root_hash": "<hex>",
  "audit_path": ["<hex>", "…"]
}
```

Verification follows RFC 9162 section 2.1.3.2 against a *trusted* root
hash supplied by the verifier (not the one embedded in the proof). A
proof MUST be rejected if the recomputed root differs from the trusted
root, if the path length is inconsistent with `(leaf_index, tree_size)`,
or if any hash fails to decode to 32 bytes.

### 4.2 Consistency Proof

The proof `PROOF(m, D[n])` per RFC 6962 section 2.1.2 demonstrates that
the tree at size `n` is an append-only extension of the tree at size `m`:

```json
{
  "old_size": 5,
  "new_size": 8,
  "old_root": "<hex>",
  "new_root": "<hex>",
  "consistency_path": ["<hex>", "…"]
}
```

Verification follows RFC 9162 section 2.1.4.2. For `old_size ==
new_size` the path MUST be empty and the roots MUST be equal.

## 5. Anti-Equivocation Semantics

Two signed tree heads with the same `log_id` and the same `tree_size`
but different `root_hash` values constitute **equivocation** (a split
view): no consistency proof can exist between them, and verifiers MUST
treat the pair as proof of log misbehavior. The signed pair of
contradictory STHs is itself portable, non-repudiable evidence.

A forked log (history rewritten after a shared prefix) fails
consistency verification from any honest old head: the consistency
path cannot reproduce the honest old root.

## 6. Conformance Vectors

`core/pkg/translog/testdata/rfc6962_golden.json` freezes a deterministic
8-leaf log built from the canonical RFC 6962 test inputs, including:

- the expected root at every tree size (matching the published
  Certificate Transparency reference vectors),
- frozen inclusion and consistency proofs,
- a deterministic STH signed with a zero-seed Ed25519 test key.

Negative vectors covered by the conformance tests: tampered leaf fails
inclusion; truncated audit path fails inclusion; equivocating roots at
equal size fail consistency; forked history fails consistency against
the honest old head; corrupt journal refuses to load.

## 7. Scope and Future Work

v1 ships the local log primitive, CLI, and proofs. Receipt issuance
does NOT yet auto-append to the log; wiring issuance (with an explicit
fail-closed block-or-degrade policy recorded in the receipt) is a
follow-up. Receipts will then carry `log_id` and `leaf_index`. The
hosted public log, monitor, and gossip network remain a commercial
(Enterprise/Certification) surface.

## 8. References

- RFC 6962 — Certificate Transparency
- RFC 9162 — Certificate Transparency Version 2.0
- RFC 8785 — JSON Canonicalization Scheme (JCS)
- `protocols/specs/rfc/receipt-format-v1.md` — HELM Receipt Format
