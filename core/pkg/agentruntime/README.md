# HELM AI Kernel Agent Runtime Package Source Owner

## Audience

Use this file when changing the durable turn-event log, the reducer append
gate, hash chaining / transparency-log anchoring, crash-recovery planning,
or model-request recomposition for HELM's first-party agent loop runtime.

## Responsibility

`core/pkg/agentruntime` owns the library-only durable spine of the HELM
agent runtime (phase 1): versioned turn events, the pure `Reduce` /
`ValidateAppend` gate, the JSONL hash-chained store, the documented
crash-recovery matrix (`PlanRecovery`), and deterministic reference-based
model-request recomposition (`ComposeRequest`). It has no executor, model,
or CLI integration; those are later phases and must route governed effects
through `core/pkg/executor` so every tool dispatch carries a Kernel
verdict.

## Design provenance

The mechanism architecture (reducer-as-append-gate, reference-based
durable model requests, crash-recovery truth table) is adapted from the
Apache-2.0 Rowboat project (`github.com/rowboatlabs/rowboat`). This is an
original Go implementation; no Rowboat code or prose is copied. HELM-native
upgrades: hash-chained events over RFC 8785 canonical JSON
(`core/pkg/canonicalize`), optional anchoring into the kernel's RFC 6962
transparency log (`core/pkg/translog`), typed infrastructure errors that
can never be recorded as tool errors, and permission events that are
advisory records referencing kernel verdicts rather than authorities.

## Invariants

- The reducer is the sole append gate. `Store.Append` validates
  existing+candidates through `ValidateAppend` before any byte is written.
- Reads fail loud: non-canonical bytes, broken hash chains, unknown
  fields, turn-ID drift, and reducer-illegal sequences are hard errors.
  There is no repair path.
- An interrupted sync tool is indeterminate and is never re-executed; an
  interrupted model call is closed and re-issued against budget.
- `InfraError` is infrastructure, never turn history.

## Validation

Run:

```bash
cd core && go test ./pkg/agentruntime/ -count=1
cd core && go test ./pkg/agentruntime/ -count=1 -race
```

Golden recomposition bytes/hashes are pinned in `compose_test.go`; a drift
there is a format change and must be reviewed as such.
