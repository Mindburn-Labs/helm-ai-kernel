# Invcheck
<!-- docs-generated: surface-readme -->

## Purpose

Active tooling surface for the `helm-ai-kernel` project. Enforces the invariant
constitution in `HELM_INVARIANTS.md`: every `INV-NNN` carries a `verify:` hint,
ids are unique, machine-checkable references resolve, and amendments arrive with
a `CONCEPT-CHANGE(INV-NNN)` commit marker.

It also owns the control registry, `controls.yaml` (binding rule R1). The
registry holds every claimed control and the text of every invariant;
`HELM_INVARIANTS.md` and `coverage-map.json` are generated from it.

## Canonical Interface

- Source path: `tools/invcheck`
- Surface type: `tooling`
- Package/source identity: `invcheck`
- Coverage record: `docs/documentation-coverage.csv`

## Local Commands

- `make inv-check` runs the constitution gate.
- `make concept-gate` runs the amendment-marker gate over `CONCEPT_RANGE`
  (default `origin/main..HEAD`). A range with no commits exits 2 rather than
  passing; CI passes the pull request's `base..head`.
- `make controls` regenerates `HELM_INVARIANTS.md` and `coverage-map.json`
  from `controls.yaml`.
- `make controls-check` runs `inv-check`, then the registry gate. It fails on an
  invalid entry; an `enforced` entry point that no binary in
  `scripts/ci/deadcode-roots.txt` reaches; a named test that `go test -list`
  does not report; a `removal_mutation` that the removal tests survive; or a
  generated file that differs from the registry. Reachability reuses the
  deadcode gate: a symbol is reachable when its package is in the roots'
  `go list -deps` graph for linux/amd64 and it is absent from
  `scripts/ci/deadcode-allowlist.txt`, which that gate keeps equal to the
  measured unreachable set.
- `GOWORK=off go test ./...` in this directory runs the concept-gate controls
  against throwaway git repositories: an unmarked invariant edit must fail, a
  marked one must pass, and an empty range must be refused. It also checks the
  registry rules against planted entries.
- `make docs-coverage` from the repository root verifies coverage for this surface.

`inv-check` self-tests against synthetic negative and positive controls before it
reads the real constitution. If any control comes back the wrong way it exits
non-zero without scanning, on the grounds that a checker which has stopped
discriminating would report a green constitution it never inspected.

Free-prose hints are reported as human-owned and are never counted as verified.

`controls` does the same: planted registry entries (no owner, an unknown status,
an unreachable or missing entry point, a missing test, a removed entry, a stale
generated file) must each fail, and a planted good entry must pass, before it
judges the real registry.

## Documentation Contract

Generated surface README. This file is a local ownership and validation contract, not the primary docs information architecture entry point. It covers the active tooling surface. Keep it aligned with the source path above and update `docs/documentation-coverage.csv` when ownership, interfaces, validation, or lifecycle status changes.
