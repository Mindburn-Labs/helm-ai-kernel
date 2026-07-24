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

## Invariant Constitution

`HELM_INVARIANTS.md` is the numbered constitution: each `INV-NNN` states a
property this kernel does not trade away and names the artifact that proves it.
Two gates keep it from decaying into prose.

```bash
make inv-check                                  # hints resolve, ids unique
make concept-gate                               # amendments carry a marker
make concept-gate CONCEPT_RANGE=main..HEAD      # over a chosen range
```

`inv-check` checks that every invariant carries a `verify:` hint, that ids are
unique, and that each backticked reference in a hint — repo path, Go test name,
`make` target — resolves in this tree. Before it reads the constitution at all it
runs synthetic negative and positive controls through itself: a block with no
hint, a duplicate id, a dangling path, an unknown test, an unknown target, a
retired entry with no successor, and one well-formed block that must come back
clean. If any control answers the wrong way the gate exits non-zero **without
scanning**, because a checker that has stopped discriminating reports a green
constitution it never inspected.

Hints that are free prose are human-owned. The gate does not check them and
prints them under a heading saying so rather than folding them into the resolved
count.

`concept-gate` fails a commit that adds, edits, or retires an invariant without a
`CONCEPT-CHANGE(INV-NNN)` marker in its message naming every id it touched.
Attribution comes from comparing parsed blocks either side of the commit, not
from diff hunks, so a change lands on the invariant that owns it however the diff
was framed. Editing the surrounding prose is not a concept change and needs no
marker; pass `-strict-any-edit` to require one on any modification of the file.

Both are registered as **advisory** gates in the `nightly` profile. They do not
block PR or merge today. Promote them with `QUALITY_STRICT=1` locally, or move
them into the `pr` profile once the constitution has settled.

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
