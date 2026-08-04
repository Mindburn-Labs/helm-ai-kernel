# Invcheck
<!-- docs-generated: surface-readme -->

## Purpose

Active tooling surface for the `helm-ai-kernel` project. Enforces the invariant
constitution in `HELM_INVARIANTS.md`: every `INV-NNN` carries a `verify:` hint,
ids are unique, machine-checkable references resolve, and amendments arrive with
a `CONCEPT-CHANGE(INV-NNN)` commit marker.

## Canonical Interface

- Source path: `tools/invcheck`
- Surface type: `tooling`
- Package/source identity: `invcheck`
- Coverage record: `docs/documentation-coverage.csv`

## Local Commands

- `make inv-check` runs the constitution gate.
- `make concept-gate` runs the amendment-marker gate over `CONCEPT_RANGE`
  (default `origin/main..HEAD`).
- `make docs-coverage` from the repository root verifies coverage for this surface.

`inv-check` self-tests against synthetic negative and positive controls before it
reads the real constitution. If any control comes back the wrong way it exits
non-zero without scanning, on the grounds that a checker which has stopped
discriminating would report a green constitution it never inspected.

Free-prose hints are reported as human-owned and are never counted as verified.

## Documentation Contract

Generated surface README. This file is a local ownership and validation contract, not the primary docs information architecture entry point. It covers the active tooling surface. Keep it aligned with the source path above and update `docs/documentation-coverage.csv` when ownership, interfaces, validation, or lifecycle status changes.
