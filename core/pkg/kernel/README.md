# HELM OSS Kernel Package Source Owner

## Audience

Use this file when changing deterministic execution, policy decision reduction, CSNF canonicalization, risk budgets, task ordering, freeze behavior, memory trust, or boundary assertions.

## Responsibility

`core/pkg/kernel` owns the runtime kernel semantics behind HELM OSS policy evaluation and governed execution. Public docs should describe the request lifecycle and trust boundary; this package owns the code-level behavior that makes those claims true.

## Public Status

Classification: `public-hub`.

Public docs should link here from:

- `helm-oss/architecture`
- `helm-oss/reference/execution-boundary`
- `helm-oss/reference/http-api`
- `helm-oss/verification`
- `helm-oss/troubleshooting`

## Source Map

- Determinism and canonicalization: `csnf*.go`, `nondeterminism.go`, `prng.go`, `total_order_log.go`.
- Boundary enforcement: `boundary_assertions.go`, `effect_boundary.go`, `context_guard.go`, `secret_ref.go`.
- Policy decision path: `cel_dp.go`, `pdp_adapter.go`, `reducer.go`.
- Runtime safety: `limiter.go`, `freeze.go`, `agent_kill.go`, `scheduler.go`, `concurrency.go`.
- Memory and event integrity: `memory_integrity.go`, `memory_trust.go`, `event_log.go`, `merkle.go`.

## Documentation Rules

- Public examples must not imply nondeterministic replay is supported unless the deterministic path is covered here and in tests.
- Claims about fail-closed behavior, budget enforcement, and policy ordering must cite this package or package tests.
- Any new externally observable kernel mode needs a public reference note and troubleshooting entry.

## Validation

Run:

```bash
cd core
go test ./pkg/kernel -count=1
cd ..
make docs-coverage docs-truth
```
