---
title: "HELM Effect Permit Signing Specification"
status: final
version: "1.0.0"
created: 2026-08-10
finalized: 2026-08-10
authors:
  - HELM Core Team
---

<!-- quantum_posture: this profile specifies classical Ed25519 signing and
makes no hybrid or post-quantum cryptographic claim. -->

# Effect Permit Signing v1

## Status and scope

Final — Normative Integrity Contract.

This document and `reference_packs/effect-permit-v1/` define the byte-exact
`effect_permit.v1` signing preimage. The protobuf `EffectPermit` message in
`protocols/proto/helm/effects/v1/effects.proto` separately owns the wire
contract. No JSON Schema is an authority for either contract.

The final status applies to this named canonical integrity profile, not to every
producer or verifier that uses the shared `EffectPermit` wire type. An existing
unversioned or differently constructed signing preimage is outside
`effect_permit.v1`. End-to-end G1 adoption requires coordinated Control Plane
producer adoption plus Data Plane and Sandbox verification against this
profile; publishing the contract alone does not prove those migrations are
integrated or deployed.

This specification does not define effect admission, connector-specific scope
evaluation, expiry policy, replay storage, or nonce consumption. Those checks
remain in the governed execution path that consumes a verified permit.

## Signing preimage

The producer MUST construct one JSON object with the following members:

| Member | Source |
| --- | --- |
| `signature_version` | literal `effect_permit.v1` |
| `permit_id` | `EffectPermit.permit_id` |
| `intent_hash` | `EffectPermit.intent_hash` |
| `verdict_hash` | `EffectPermit.verdict_hash` |
| `plan_hash` | `EffectPermit.plan_hash`, or `""` when absent |
| `policy_hash` | `EffectPermit.policy_hash`, or `""` when absent |
| `effect_type` | bare HELM value: `READ`, `WRITE`, `DELETE`, `EXECUTE`, `NETWORK`, or `FINANCE` |
| `connector_id` | `EffectPermit.connector_id` |
| `scope.allowed_action` | `EffectPermit.scope.allowed_action` |
| `scope.allowed_params` | ordered array, or `[]` when absent |
| `scope.deny_patterns` | ordered array, or `[]` when absent |
| `resource_ref` | `EffectPermit.resource_ref` |
| `expires_at` | instant normalized to UTC and rendered as RFC3339Nano |
| `single_use` | `EffectPermit.single_use` |
| `nonce` | `EffectPermit.nonce` |
| `issued_at` | instant normalized to UTC and rendered as RFC3339Nano |
| `issuer_id` | `EffectPermit.issuer_id` |
| `evidence_bindings` | string map, or `{}` when absent |

Array order is data and MUST be preserved. UTC fractional seconds MUST omit
trailing zeros. A protobuf enum name such as `EFFECT_TYPE_WRITE` MUST be mapped
to the bare value `WRITE` before signing.

The object MUST be encoded with HELM Interoperable JCS as specified by
`protocols/specs/rfc/canonical-json-v1.md`. The canonical UTF-8 bytes, without a
trailing newline, are the bytes supplied to the signer. `signature` is not a
member of the preimage.

Adding a covered field or changing any construction rule requires a new
signature-version literal. A producer MUST NOT silently widen v1.

## Signature profile

The preimage is algorithm-neutral. The current Kernel `SignPermit`/`VerifyPermit`
profile uses Ed25519 and stores the 64-byte signature as 128 lowercase hex
characters in `EffectPermit.signature`. The reference index prefixes public
keys and detached signatures with `ed25519:` so their encoding and algorithm
are explicit; the canonical permit artifact retains the production raw-hex
wire value.

## Verification

A verifier MUST:

1. parse the permit using the protobuf wire contract or an equivalent field-complete view;
2. reject an absent signature;
3. reconstruct every member in the table above, including empty defaults and UTC timestamps;
4. apply Interoperable JCS;
5. verify the signature over those bytes under an authorized issuer key; and
6. only then perform the deployment's admission, replay, liveness, and connector-scope checks.

Successful signature verification proves integrity and issuer-key possession.
It does not by itself prove that a permit is live, unconsumed, in scope, or
accepted by a deployed connector.

## Reference pack

`reference_packs/effect-permit-v1/` contains:

- a fully populated WRITE permit;
- a READ normalization vector covering absent optional fields, nil collections,
  a numeric UTC offset, and fractional seconds;
- canonical permit and signing-payload bytes with SHA-256 indices;
- fixed Ed25519 public-key and signature material; and
- executed negative mutations for unsigned input, non-canonical signature
  casing, signature corruption,
  covered-field and list-order tampering, missing domain separation, null
  collections, and omitted UTC normalization.

The Go parity test derives the pack from `EffectPermitSigningPayload`. The
stdlib-only Python verifier reconstructs the preimage from the permit artifact
and executes every declared mutation.

```bash
make verify-effect-permit-vectors
```

The target is included in `make verify-fixtures` and therefore in the fixture
gate used by CI.
