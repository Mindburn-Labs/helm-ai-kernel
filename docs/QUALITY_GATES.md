---
title: Quality Gates
last_reviewed: 2026-05-12
---

# Quality Gates

HELM AI Kernel uses a Make-first quality gate pipeline. The root `Makefile` is the
canonical local interface; `scripts/ci/quality.py` executes the gate registry in
`scripts/ci/quality-gates.json`.

## Quick Start

```bash
make quality-pr
make quality-merge
make quality-release
make quality-nightly

make quality-list
make quality-explain CHECK=json-schemas
```

Use focused gates when working on one surface:

```bash
make quality-typecheck
make quality-contracts
make quality-security
make quality-runbooks
make quality-mutation
make quality-flake
make quality-impact
```

## Profiles

| Profile | Command | Purpose |
| --- | --- | --- |
| PR | `make quality-pr` | Fast documentation, hygiene, Go, TCB, boundary, fixture, and impacted SDK/UI checks. |
| Merge | `make quality-merge` | Full retained-surface gate with race tests, SDKs, contracts, deployment smoke, and release smoke. |
| Release | `make quality-release` | Release-readiness gate plus reproducible binaries, SBOM, VEX, Cosign bundle verification when available, and release smoke. |
| Nightly | `make quality-nightly` | Advisory mutation, flake, vulnerability, runbook, migration, dependency hygiene, schema, and benchmark checks. |

`make quality-pr` runs path-scoped package gates only when changed files impact
that surface. Override detection with `QUALITY_CHANGED_FILES`, using newline or
comma-separated paths.

## Blocking and Advisory Gates

Existing CI truth remains blocking: docs truth, presentation hygiene, Go lint,
build, tests, TCB import isolation, boundary manifest drift, fixture
verification, contract drift, deployment smoke, and release smoke.

New noisy gates are Advisory by default: `secrets`, `vuln-audit`,
`mutation-core`, `flake-core`, `runbooks`, `migrations`,
`dependency-hygiene`, and `benchmark-report`. Promote them to blocking locally
or in CI with:

```bash
QUALITY_STRICT=1 make quality-nightly
```

## Gate Registry

The registry owns:

- gate id, title, command, timeout, and advisory/blocking status
- profile membership
- path impact filters for package-specific checks

Before changing profiles, run:

```bash
make quality-self-test
make quality-list
make quality-explain CHECK=<gate-id>
```

## Failure Interpretation

Blocking failures exit non-zero and should stop merge or release. Advisory
failures emit warnings and allow the profile to complete unless
`QUALITY_STRICT=1` is set. In GitHub Actions, the runner emits native
`::warning::` and `::error::` annotations.

If a generated contract gate fails, regenerate the relevant output and commit
the drift only when the source contract changed intentionally. If a runbook or
migration coverage gate fails, either add the missing operational coverage or
document why the surface is not part of the retained OSS lifecycle.
