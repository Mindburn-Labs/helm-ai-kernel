# Reference Packs
<!-- docs-generated: surface-readme -->
<!-- quantum_posture: reference packs pin classical Ed25519 signing vectors; no post-quantum cryptographic control is added or claimed. -->

## Purpose

Active surface for the `helm-ai-kernel` project.

## Canonical Interface

- Source path: `reference_packs`
- Surface type: `surface`
- Package/source identity: `reference_packs`
- Coverage record: `docs/documentation-coverage.csv`

## Local Commands

- `make docs-coverage` from the repository root verifies coverage for this surface.
- `make verify-approval-ceremony-vectors` regenerates nothing and verifies the
  source-owned Go fixtures plus independent Python implementations for the
  approval, consumption, and dispatch-admission contracts.
- `make verify-connector-release-authority-vectors` verifies the signed
  certified-to-revoked release-authority chain in Go and independent Python.
- `make verify-effect-close-vectors` verifies the connector acknowledgement
  and Kernel close receipt in Go and independent Python.
- `make verify-effect-disposition-vectors` verifies the Control Plane
  disposition command and Kernel receipt in Go and independent Python.
- `make verify-evidence-pack-successor-vectors` verifies sealed-pack lineage,
  operational evaluation, progress, and mutually exclusive final/censored
  measurement addenda in Go and independent Python.
- `make verify-receipt-v5-vectors` verifies the mainline Kernel receipt.v5
  signing preimage in source-owned Go and independent stdlib Python.
- `make verify-effect-permit-vectors` verifies the byte-exact
  `effect_permit.v1` signing contract in Go and independent Python.

## Receipt v5 pack

`receipt-v5/` pins the exact 13-member signing object, canonical payload,
classical Ed25519 test signature, safe-integer boundary, empty signed members,
and escaping cases defined by
`protocols/specs/receipts/receipt-v5.md`. It proves portable integrity-contract
verification only; unsigned receipt fields and a self-declared public key remain
untrusted.

## Approval ceremony packs

- `approval/` covers challenge, assertion, authority, and quorum projection.
- `approval-consumption-v1/` covers the signed single-use consumption record.
- `approval-dispatch-admission-v1/` covers the signed, short-lived pre-effect
  admission and its exact consumption, connector-authority, and liveness
  bindings. It is an internal interoperability fixture, not evidence of Data
  Plane enforcement, current connector certification/revocation, effect start,
  deployment, or production release authority.

## Connector release authority pack

`connector-release-authority-v1/` covers canonical self-hashes, the
source-authority Ed25519 signature, exact connector version and provenance
bindings, validity, and a terminal revocation revision. It proves portable
contract verification only; a signed historical statement is not current state
without the separate durable registry and near-effect admission checks.

## Effect close pack

`effect-close-v1/` covers connector acknowledgement and Kernel close receipt
self-hashes, independent Ed25519 signature domains, exact reservation and
EvidencePack bindings, explicit `APPLIED` versus `NOT_APPLIED` outcomes, and
negative mutations. It proves portable contract verification only; it is not
evidence of a deployed connector acknowledgement publisher, Data Plane close
adapter, source-system reconciliation, or production release authority.

## Effect disposition pack

`effect-disposition-v1/` covers a Control Plane-signed command bound to an exact
active FENCE and reservation head plus a chained Kernel-signed receipt. Negative
vectors enforce pinned identities, exact bindings, predecessor order, and
`execution_authority: NONE`. It proves portable contract verification only; it
is not evidence of deployed cross-plane delivery, connector cancellation or
compensation, source reconciliation, or production release authority.

## Effect permit pack

`effect-permit-v1/` covers the canonical permit artifact, byte-exact signing
preimage, UTC and empty-field normalization, Ed25519 test signatures, and
executed negative mutations. It proves portable integrity verification only;
admission, replay protection, liveness, connector scope, deployment, and
production release authority remain separate checks.

## EvidencePack successor pack

`evidence-pack-successor-v1/` pins the frozen activation, outcome-contract,
measurement-plan, and window identity carried from a sealed effect-time pack
through operational evaluation and final or censored measurement. Its two
ProofGraph chains and negative mutations cover deterministic duplicate
identity, conflicting evidence, lineage substitution, progress/finality type
confusion, terminal closure, and dangling parents. It proves portable contract
and in-memory reference-graph behavior only; it does not prove durable service
persistence, deployment, observed provider outcomes, or production acceptance.

## Documentation Contract

Generated surface README. This file is a local ownership and validation contract, not the primary docs information architecture entry point. It covers the active surface. Keep it aligned with the source path above and update `docs/documentation-coverage.csv` when ownership, interfaces, validation, or lifecycle status changes.
