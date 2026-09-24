# Tcbcheck
<!-- docs-generated: surface-readme -->

## Purpose

Active tooling surface for the `helm-ai-kernel` project.

## Canonical Interface

- Source path: `tools/tcbcheck`
- Surface type: `tooling`
- Package/source identity: `tcbcheck`
- Coverage record: `docs/documentation-coverage.csv`

## Local Commands

- `make docs-coverage` from the repository root verifies coverage for this surface.

## Gate Behaviour

Before scanning `core/pkg`, `tcbcheck` scans a synthetic tree with one file per
forbidden fragment and one clean file, and exits 2 unless exactly the fragment
files are flagged. A parse error, a missing `core/pkg`, or zero scanned files also
exit 2; violations exit 1. `GOWORK=off go test ./...` here runs those cases.

## Documentation Contract

Generated surface README. This file is a local ownership and validation contract, not the primary docs information architecture entry point. It covers the active tooling surface. Keep it aligned with the source path above and update `docs/documentation-coverage.csv` when ownership, interfaces, validation, or lifecycle status changes.
