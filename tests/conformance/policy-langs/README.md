# Cross-language policy equivalence corpus

This directory holds the differential test suite for HELM's three
supported policy front-ends — CEL, OPA/Rego, and Cedar. Each logical
rule is expressed once per language (a "triple"); the harness compiles
all three forms, drives 100 deterministically-randomized requests
through them, and asserts the verdicts are byte-identical.

Workstream F / F1 — Phase 3 of the helm-oss 100% SOTA execution plan.

## Layout

```
corpus/
  cel/
    01-allow-view.cel
    02-admin-delete.cel
    03-deny-drop.cel
    04-alice-view.cel
    05-view-or-editor-edit.cel
  rego/
    01-allow-view.rego
    02-admin-delete.rego
    ...
  cedar/
    01-allow-view.cedar
    ...
equivalence_test.go
harness.go
README.md
```

## Corpus selection criteria

The five triples were chosen to exercise the discriminating axes between
CEL, Rego, and Cedar — the places where languages most often diverge in
practice. Each triple is one logical rule:

| # | Name                  | Logical rule                                                                | Why it is in the corpus                                                                                                |
|---|-----------------------|-----------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| 1 | allow-view            | `allow if action == "view"`                                                 | Baseline: simplest possible permit. If this fails, the harness itself is broken.                                       |
| 2 | admin-delete          | `allow if action == "delete" AND role == "admin"`                           | Conjunction + a context value. Catches missing context wiring in any single language.                                  |
| 3 | deny-drop             | `allow if action != "drop"`                                                 | Negation. Cedar's `when { action != Action::"drop" }` exercises a different code path from `permit(action == ...)`.    |
| 4 | alice-view            | `allow if principal == "alice" AND action == "view"`                        | Principal equality + UID coercion. Confirms Cedar's bare-string -> `Principal::"alice"` default mapping works.         |
| 5 | view-or-editor-edit   | `allow if action == "view" OR (action == "edit" AND role == "editor")`      | Disjunction with mixed predicates. Cedar handles this via two `permit` clauses; Rego via two rule heads; CEL via `||`. |

Triples are intentionally action-and-context-driven so the Cedar
evaluator can wrap bare `principal`/`resource` strings as
`Principal::"<value>"` / `Resource::"<value>"` UIDs without forcing the
corpus to pre-encode entity types in every language's source.

## What the suite is **not** trying to prove

- **Schema validation**: Cedar schema files are out of scope. The suite
  exercises authorization decisions, not type-check diagnostics.
- **Obligations / advice**: All three front-ends can return obligations,
  but obligations carry language-specific data shapes that the v1
  equivalence axis does not require. Verdict equality is the contract.
- **Performance parity**: The Rego leg goes through OPA's full rego.v1
  prepare pipeline; CEL is a hand-rolled program; Cedar is a parsed
  policy set. Latency comparisons belong in `benchmarks/`, not here.
- **Deeply non-trivial Cedar features** (entity hierarchies, attribute
  predicates on entities) are deliberately not exercised — those
  features have no clean CEL/Rego mapping. The harness uses Cedar's
  `context.<field>` form, which all three languages express identically.

## Running the suite

```
cd core
go test ./tests/conformance/policy-langs/...
```

The seed for each triple is derived from its base name via an FNV-1a
fold (see `equivalence_test.go::seedFor`), so a divergence produces a
reproducible counter-example printed inline in the failure message.

## Adding a triple

1. Pick the next free numeric prefix (`06-...`).
2. Drop one source file per language under `corpus/{cel,rego,cedar}/`.
3. Append the base name to the `triples` slice in `equivalence_test.go`.
4. Re-run `go test ./tests/conformance/policy-langs/...`. If a divergence
   surfaces, either reshape the rule or document the gap in
   `docs/architecture/policy-languages.md` (Workstream B5).

## Relationship to the Conformance Profile

The acceptance bar for the proposed Tier-2 conformance axis "policy
language equivalence" (Profile v1.1) is exactly this suite plus the
documented gap list. See `docs/architecture/formal-soundness.md` and
`tests/conformance/profile-v1/checklist.yaml`.
