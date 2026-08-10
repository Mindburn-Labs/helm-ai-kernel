---
title: "HELM Kernel Receipt v5 Signing Preimage"
status: final
version: "1.0.0"
created: 2026-08-10
authors:
  - HELM Core Team
---

# HELM Kernel Receipt v5 Signing Preimage

<!-- quantum_posture: this specification is algorithm-neutral. Its reference
pack demonstrates the classical Ed25519 profile only and makes no hybrid or
post-quantum claim. -->

## Status and scope

Final — Normative Standard.

This document and `reference_packs/receipt-v5/` define the integrity contract
for the mainline Kernel `contracts.Receipt` when `signature_version` is exactly
`receipt.v5`. They do not define the HTTP or gRPC wire contract, the launch
profile in `receipt-format-v1.md`, a chain hash, or the legacy unversioned
receipt preimages.

## Signing object

The signing object MUST contain exactly these 13 members. Every member MUST be
present even when its value is the empty string; none is optional.

| Member | Value |
| --- | --- |
| `signature_version` | the literal string `receipt.v5` |
| `receipt_id` | the receipt's `receipt_id` |
| `decision_id` | the receipt's `decision_id` |
| `effect_id` | the receipt's `effect_id` |
| `status` | the receipt's `status` |
| `output_hash` | the receipt's `output_hash`, including an empty value |
| `prev_hash` | the receipt's `prev_hash`, including an empty value |
| `lamport_clock` | the receipt's unsigned integer `lamport_clock` |
| `args_hash` | the receipt's `args_hash`, including an empty value |
| `verdict` | the receipt's `verdict`, including an empty value |
| `reason_code` | the receipt's `reason_code`, including an empty value |
| `policy_hash` | the receipt's `policy_hash`, including an empty value |
| `session_id` | the receipt's `session_id`, including an empty value |

No other receipt member enters this preimage. In particular `timestamp`,
`executor_id`, `correlation_id`, `metadata`, `decision_hash`, `key_id`,
`public_key_set`, transparency fields, and the signature metadata are unsigned
transport claims. A verifier MUST NOT treat them as authenticated by the
`receipt.v5` signature.

## Canonical bytes

The signing object MUST be serialized using
`protocols/specs/rfc/canonical-json-v1.md` and MUST satisfy that standard's
interoperable subset. The result is the signing payload exactly as emitted:
UTF-8, no whitespace between tokens, no byte-order mark, and no trailing
newline.

The input to canonicalization is a decoded JSON data-model value, not an
arbitrary byte string. Its strings are Unicode values. The reference-pack
files are valid UTF-8 JSON, and the source-owned parity test rejects a fixture
that is not. Handling a malformed byte stream before it becomes a JSON value
belongs to the containing wire or transport contract, which this preimage
profile does not define. In particular, this profile does not claim that a
verifier receiving only an already-decoded object can recover and reject an
earlier malformed encoding.

`lamport_clock` is the only numeric member. Its value MUST be no greater than
9007199254740991 (2^53−1). Producers MUST refuse a larger value rather than
publishing bytes that a strict RFC 8785 implementation cannot reproduce.

## Signature profile

The preimage is independent of the signature algorithm. The active classical
profile signs the canonical bytes with Ed25519 and carries:

- the 64-byte signature as 128 lowercase hexadecimal characters in
  `signature`;
- the 32-byte public key as 64 lowercase hexadecimal characters in
  `public_key_set.ed25519`;
- `signature_algorithm: ed25519` and `signature_profile: classical`.

`key_id`, `public_key_set`, `signature_algorithm`, and `signature_profile` do
not enter the preimage. They are routing metadata, not trust roots. A verifier
MUST use independently trusted key material; a receipt's self-declared public
key is insufficient by itself.

## Verification

A conforming verifier MUST:

1. require `signature_version` to equal `receipt.v5` and refuse a missing or
   unknown version for this profile;
2. require all 13 signing members, including empty-valued members;
3. reject any number outside the interoperable subset;
4. construct only the signing object above and canonicalize it byte-for-byte;
5. verify the signature with an independently trusted key and the declared
   algorithm profile; and
6. fail closed on any construction, decoding, trust, or signature error.

A verifier MUST NOT retry a declared `receipt.v5` signature against a legacy
or whole-receipt preimage. Legacy unversioned receipt compatibility is outside
this conformance target.

Adding, removing, or renaming a signed member requires a new signature-version
constant and a new preimage specification. The meaning of `receipt.v5` MUST
never be widened in place.

## Reference pack

`reference_packs/receipt-v5/vectors.json` pins three positive cases:

- a policy DENY with populated governance fields;
- a successful executor receipt with deliberately empty governance fields and
  `lamport_clock` at the safe-integer boundary; and
- string escaping including quote, reverse solidus, tab, U+2028, U+2029, and a
  supplementary-plane character.

The negative matrix rejects a governance-field substitution, a modified
signature, a Lamport clock above the interoperable boundary, and omission of
an empty signed member. The source-owned Go parity test and independent
stdlib-Python verifier both run from `make verify-fixtures`.

The pack's deterministic test key uses the 32-byte Ed25519 seed `0x2a`
repeated 32 times. This is public, non-secret fixture material and MUST NOT be
used outside tests.
