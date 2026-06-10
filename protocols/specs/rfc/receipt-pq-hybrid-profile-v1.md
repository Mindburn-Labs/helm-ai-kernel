---
title: "HELM Receipt PQ-Hybrid Signature Profile"
status: draft
version: "1.0.0"
created: 2026-06-10
authors:
  - HELM Core Team
---

# RFC: HELM Receipt PQ-Hybrid Signature Profile v1 (Ed25519 + ML-DSA-65)

## Abstract

This document specifies the post-quantum hybrid signature profile for HELM
governance receipts. A hybrid-profile receipt carries one composite envelope
containing both a classical Ed25519 signature and a post-quantum ML-DSA-65
(FIPS 204) signature computed over the same canonical preimage. The profile
exists so receipts retain evidentiary value after the classical algorithm era
ends: a harvest-now/forge-later adversary who breaks Ed25519 cannot forge a
hybrid receipt without also breaking ML-DSA-65.

## Status

Draft — extends [HELM Receipt Format v1.0](receipt-format-v1.md). The
classical receipt profile defined there remains valid and is not deprecated
by this document.

### Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Profiles

A receipt signature belongs to exactly one of two profiles, detected from the
`signature` field itself:

| Profile     | Detection                               | Algorithms                |
| ----------- | --------------------------------------- | ------------------------- |
| `classical` | Signature is a bare hex string          | Ed25519                   |
| `hybrid`    | Signature starts with literal `hybrid:` | Ed25519 **and** ML-DSA-65 |

Algorithm identifiers reuse the existing kernel registry: `ed25519`
(`crypto.AlgorithmEd25519`) and `ml-dsa-65` (`crypto.AlgorithmMLDSA65`,
FIPS 204 / `mldsa65`).

## 2. Signing Preimage

Both sub-signatures of a hybrid envelope MUST be computed over the **same**
preimage as the classical profile — the canonical receipt string defined by
`crypto.CanonicalizeReceipt`:

```
receipt_id:decision_id:effect_id:status:output_hash:prev_hash:lamport_clock:args_hash
```

Fields are joined with the `:` separator. Content addressing of receipt
identifiers continues to use JCS (RFC 8785) + SHA-256 per Receipt Format
v1 §4. The hybrid profile changes the signature envelope only; it MUST NOT
alter the preimage, canonicalization, or content addressing.

## 3. Hybrid Envelope

The composite signature is a single string stored in the receipt
`signature` field:

```
hybrid:<ed25519_signature_hex>:<mldsa65_signature_hex>
```

- `ed25519_signature_hex` MUST be exactly 128 hex characters (64 bytes).
- `mldsa65_signature_hex` MUST be exactly 6586 hex characters (3293 bytes,
  `mldsa65.SignatureSize`).
- The ML-DSA-65 signature MUST be produced in deterministic mode
  (FIPS 204 deterministic variant, empty context string), so a hybrid
  envelope over a fixed preimage and keypair is byte-reproducible.

The composite public key, where published, uses the same shape:

```
hybrid:<ed25519_public_key_hex>:<mldsa65_public_key_hex>
```

### 3.1 Issuance

Issuance of hybrid receipts is opt-in per kernel instance via the receipt
profile flag (`HELM_RECEIPT_PROFILE=hybrid`). Signing is fail-closed: if
**either** sub-signature cannot be produced, the receipt MUST NOT be emitted.
The PQ keypair lives in the same keyring/data directory as the classical root
key (`root.mldsa65.key` beside `root.key`, hex-encoded 32-byte seed) and
follows the same rotation lifecycle: rotating the root key rotates both
components; revoking the key ID revokes both.

## 4. Verification Policy

Verification is profile-strict and fail-closed:

1. **Hybrid profile** — a verifier encountering a `hybrid:` envelope MUST
   verify **both** the Ed25519 and the ML-DSA-65 sub-signatures over the
   preimage in §2. If either sub-signature is invalid, missing, or malformed,
   verification MUST fail. A verifier MUST NOT accept a hybrid receipt on the
   strength of the Ed25519 component alone — there is no silent downgrade to
   classical-only acceptance.
2. **Classical profile** — a bare-hex Ed25519 signature remains valid under
   the classical profile. This document does not retroactively invalidate
   classical receipts; deployments MAY layer a policy cutover date after
   which new issuance must be hybrid, but verification of previously issued
   classical receipts is unaffected.
3. **Profile confusion** — a hybrid envelope presented to a classical-only
   verifier MUST fail verification (the `hybrid:` prefix is not valid hex,
   and classical verifiers MUST NOT strip it). A classical signature
   presented where the verification policy requires the hybrid profile MUST
   fail.
4. **Missing PQ key** — a verifier asked to verify a hybrid receipt without
   access to the signer's ML-DSA-65 public key MUST fail rather than verify
   the classical component only.

The reference verifier is `crypto.VerifyReceiptProfile` /
`crypto.HybridVerifier` in `core/pkg/crypto/hybrid_verifier.go`.

## 5. Conformance Vectors

Golden vectors live at
`core/pkg/crypto/testdata/receipt_pq_hybrid_profile_v1.json` and are
regenerated deterministically from fixed seeds (Ed25519 seed `0x42` × 32,
ML-DSA-65 seed `0x42` × 32). The vector set MUST include at minimum:

| Vector                                      | Expected |
| ------------------------------------------- | -------- |
| Valid hybrid envelope, both signatures good | PASS     |
| Good Ed25519 + corrupted ML-DSA-65          | FAIL     |
| Corrupted Ed25519 + good ML-DSA-65          | FAIL     |
| Hybrid envelope presented as classical      | FAIL     |
| Classical envelope under classical profile  | PASS     |

## 6. Security Considerations

- **Harvest-now/forge-later**: classical-only receipts signed today can be
  forged once Ed25519 falls; hybrid receipts remain unforgeable while
  ML-DSA-65 (NIST category 3) stands.
- **Fail-closed composition**: AND-composition of the two algorithms means
  the envelope is at least as strong as the stronger component; OR-fallback
  is explicitly prohibited (§4).
- **Determinism**: deterministic ML-DSA-65 signing avoids nonce-misuse
  classes and keeps EvidencePacks and proof graphs byte-reproducible across
  platforms.
- **Size**: a hybrid envelope adds ~3.3 KB per receipt. Deployments with
  tight storage budgets keep the classical profile until their cutover date.

## 7. References

- RFC 2119 — Key Words for use in RFCs
- RFC 8785 — JSON Canonicalization Scheme
- FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
- HELM Receipt Format v1.0 (`receipt-format-v1.md`)
- ePrint 2025/2025 — hybrid signatures during the PQ transition
