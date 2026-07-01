---
title: Quantum Posture
last_reviewed: 2026-07-01
---

# Quantum Posture

HELM receipt signing is profile-based. Classical receipt signing remains the
default. A configured Kernel instance can emit PQ-hybrid receipts by setting
the receipt profile to `hybrid`.

## Supported Receipt Profile

The hybrid receipt profile signs the same canonical receipt preimage with both:

- Ed25519
- ML-DSA-65

The current Kernel receipt contract exposes the profile through the
`signature` envelope, not through separate receipt metadata fields. A hybrid
receipt has this envelope shape:

```yaml
signature: "hybrid:<ed25519_hex>:<mldsa65_hex>"
```

Verification code should use `crypto.ReceiptSignatureProfile` to detect the
envelope profile, or `crypto.VerifyReceiptRequiredProfile` when the caller
requires `crypto.ReceiptProfileHybrid`. Hybrid-required verification fails
closed if the caller asks for hybrid verification and receives Ed25519-only
material.

## Current Boundary

This profile protects receipt authenticity for configured Kernel receipt paths.
It does not change every outside edge around a HELM install. Treat these as
separate checks:

- browser or visitor TLS key agreement
- certificate authentication
- SSH keys
- KMS envelopes
- identity provider tokens
- third-party service signatures

Hashing and symmetric encryption are separate primitives. The urgent migration
surface is public-key signing and key agreement, not SHA-256 receipt hashes.

## Verify The Claim

When reviewing a receipt, derive the profile from the emitted `signature`
envelope before describing the posture. If the signature is Ed25519-only,
describe it as `classical`. If the signature uses the `hybrid:` envelope and
the caller requires `hybrid`, both the Ed25519 and ML-DSA-65 signatures must
verify.
