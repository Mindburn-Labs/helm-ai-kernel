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

## Documentation Contract

Generated surface README. This file is a local ownership and validation contract, not the primary docs information architecture entry point. It covers the active surface. Keep it aligned with the source path above and update `docs/documentation-coverage.csv` when ownership, interfaces, validation, or lifecycle status changes.
