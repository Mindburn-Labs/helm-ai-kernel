---
title: Guardian 6-Gate Pipeline — Code Map
---

# Guardian 6-Gate Pipeline — Code Map

This document reconciles the README claim of a "6-gate Guardian pipeline (Freeze → Context → Identity → Egress → Threat → Delegation)" with the actual implementation. The six gates are **real and wired via the functional-options pattern** in [core/pkg/guardian/guardian.go](../../core/pkg/guardian/guardian.go), not packaged as six files named after the gates. Both README and formal spec (`proofs/GuardianPipeline.tla`) number them consistently.

## Gate-to-code mapping

| # | Gate | Configuration | Implementation package | Invariant source |
|---|------|---------------|------------------------|------------------|
| 1 | **Freeze** | `WithFreezeController(*kernel.FreezeController)` | [core/pkg/kernel/freeze.go](../../core/pkg/kernel/) | Global kill switch; fail-closed if tripped. |
| 2 | **Context** | `WithContextGuard(*kernel.ContextGuard)` | [core/pkg/kernel/](../../core/pkg/kernel/) | Environment mismatch detection; denies on runtime divergence. |
| 3 | **Identity** | `WithIsolationChecker(*identity.IsolationChecker)` | [core/pkg/identity/](../../core/pkg/identity/) | Tenant isolation + principal verification. |
| 4 | **Egress** | `WithEgressChecker(*firewall.EgressChecker)` | [core/pkg/firewall/](../../core/pkg/firewall/) | Empty-allowlist-denies; schema-pinned tool contracts. |
| 5 | **Threat** | `WithThreatScanner(*threatscan.Scanner)` | [core/pkg/threatscan/](../../core/pkg/threatscan/) | Prompt-injection + tool-poisoning + DDIPE + 12 rule sets. |
| 6 | **Delegation** | `WithDelegationStore(identity.DelegationStore)` | [core/pkg/identity/](../../core/pkg/identity/) + [core/pkg/delegation/](../../core/pkg/delegation/) | AIP delegation chain verification; AITH time-bound/revocable/narrowing. |

Each gate is an independent, opt-in Option passed to `guardian.New(opts ...GuardianOption)`. A Guardian with zero gates configured is still fail-closed at the firewall boundary (see [core/pkg/firewall/firewall.go:57,72](../../core/pkg/firewall/firewall.go)), but production deployments should wire all six.

## Why the gates are not one-file-each

The gates each touch a different concern (freeze semantics differ from identity isolation which differs from threat scanning). Forcing them into a single file per gate would collapse meaningful architectural boundaries:
- **Freeze** logically belongs to the kernel (it's a global state, not a per-request check).
- **Context** belongs to the kernel for the same reason (environment state is kernel-owned).
- **Identity** belongs with the crypto identity types in `core/pkg/identity/`.
- **Egress** is the fail-closed firewall — it's the ground truth of "allowed tools."
- **Threat** has enough internal complexity (ensemble voting, rule sets) to deserve its own package.
- **Delegation** is a distinct protocol (AIP + AITH) and shares types with `identity/`.

`guardian.go` composes them via the Options pattern. The gate *order* is invariant: the sequence in `guardian.EvaluateDecision(...)` is `Freeze → Context → Identity → Egress → Threat → Delegation`, the same order as the TLA+ spec at [proofs/GuardianPipeline.tla](../../proofs/GuardianPipeline.tla) and the README table.

## Gate numbering in comments

Where gates are referenced in code comments, the convention is `§Gate N`:

```go
// core/pkg/guardian/guardian.go:154
delegationStore   identity.DelegationStore   // Delegation session store (§Gate 6)
```

## Verification

- **Model check**: [.github/workflows/apalache.yml](../../.github/workflows/apalache.yml) runs the `GuardianPipeline` TLA+ spec in CI.
- **Chaos drill**: [.github/workflows/chaos-drill.yml](../../.github/workflows/chaos-drill.yml) `guardian-panic-path-fails-closed` scenario verifies the pipeline preserves fail-closed semantics under panic.
- **Fuzz**: [.github/workflows/fuzz.yml](../../.github/workflows/fuzz.yml) fuzzes `DecisionRequest` shape through all 6 gates.
- **Unit**: every gate has focused tests in [core/pkg/guardian/](../../core/pkg/guardian/) — see `guardian_delegation_test.go`, `session_history_test.go`, `temporal_test.go`, `privilege_test.go`, etc.

## Reading path

To understand the pipeline in source, follow in this order:
1. [guardian.go](../../core/pkg/guardian/guardian.go) — struct, Options, `EvaluateDecision` entry point.
2. Each gate's implementation package per the table above.
3. [proofs/GuardianPipeline.tla](../../proofs/GuardianPipeline.tla) — formal spec of the same order.

---

*Part of the Phase 0 truth-gate. Last updated 2026-04-15.*
