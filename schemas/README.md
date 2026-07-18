# Schemas
<!-- docs-generated: surface-readme -->

## Purpose

Active surface for the `helm-ai-kernel` project.

## Canonical Interface

- Source path: `schemas`
- Surface type: `surface`
- Package/source identity: `schemas`
- Coverage record: `docs/documentation-coverage.csv`

## Local Commands

- `make docs-coverage` from the repository root verifies coverage for this surface.
- `make verify-connector-release-authority-vectors` compiles and exercises the
  canonical `connector_release.json` authority and detached-signature envelope,
  then verifies cross-statement semantics in Go and independent Python.
- `make verify-effect-close-vectors` verifies connector acknowledgement and
  Kernel close-receipt hashing/signatures in Go and independent Python.

## Connector release authority

`connector_release.json` is the source-owned exact-version authority contract,
not candidate connector metadata. `connector_release_authority_envelope.json`
wraps it with the detached Ed25519 signature. See
`docs/operations/connector-release-authority.md` for trust, revocation, and
current-state boundaries.

## Effect close

`connector_effect_acknowledgement.json` and its detached-signature envelope
define connector evidence about `APPLIED` versus `NOT_APPLIED`.
`effect_close_receipt.json` is the separate Kernel-signed terminal statement
that binds that evidence to an exact reservation head and sealed EvidencePack.
The connector acknowledgement alone never authorizes `COMPLETED`.

## Documentation Contract

Generated surface README. This file is a local ownership and validation contract, not the primary docs information architecture entry point. It covers the active surface. Keep it aligned with the source path above and update `docs/documentation-coverage.csv` when ownership, interfaces, validation, or lifecycle status changes.
