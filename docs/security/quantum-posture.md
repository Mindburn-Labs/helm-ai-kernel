---
title: Quantum Posture
last_reviewed: 2026-07-02
quantum_posture: hybrid_when_configured
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

## Tenant KMS

Tenant KMS keys are still classical Ed25519 key material. PR #168 added
key-epoch posture metadata and policy-aware verification helpers so a caller
that requires hybrid or PQ verification is rejected instead of silently
accepting the classical tenant key. That is downgrade resistance, not
post-quantum tenant key material. Tenant KMS should be described as `classical`
until an ML-DSA/PQ-backed provider exists and is verified.

## Public Web Boundary

The public Mindburn/HELM web properties are not evidence that every transport,
identity, origin, and external-service edge is post-quantum protected. In a
late 2026-07-01 UTC check, `mindburn.org` and `helm.docs.mindburn.org` both
negotiated the TLS 1.3 group
`X25519MLKEM768` when tested with an OpenSSL 3.6 client that offered that
group. That proves PQ-hybrid visitor-to-Cloudflare key agreement for clients
that support it.

The same test showed classical ECDSA certificate authentication
(`ecdsa_secp256r1_sha256`). A 2026-07-02 in-app browser check of the
`mindburn.org` Cloudflare dashboard showed SSL/TLS `Full (strict)`, standard
Edge Certificates controls, global Authenticated Origin Pulls off, zone-level
Authenticated Origin Pulls on, and no uploaded zone-level or per-hostname custom
TLS client certificates. Do not describe the public website, docs host, or
origin path as having post-quantum authentication until Cloudflare visitor-edge
authentication or origin ML-DSA COTS/AOP is configured and verified fail-closed
against classical downgrade.

## Verify The Claim

When reviewing a receipt, derive the profile from the emitted `signature`
envelope before describing the posture. If the signature is Ed25519-only,
describe it as `classical`. If the signature uses the `hybrid:` envelope and
the caller requires `hybrid`, both the Ed25519 and ML-DSA-65 signatures must
verify.
