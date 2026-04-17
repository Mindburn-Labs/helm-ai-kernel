---
title: Path-Aware Policy Evaluation in HELM
---

# Path-Aware Policy Evaluation in HELM

**Why this doc exists**: a recurring buyer question is "can HELM's policy see the session history, or just the current request?" The short answer is yes — this document explains how.

## The formal claim

HELM's policy evaluator is **path-aware**, not stateless. Policies can condition on the full execution path of a session — previous tool calls, their outcomes, and the Lamport sequence. This is strictly more expressive than per-action checks, per arXiv [2603.16586](https://arxiv.org/abs/2603.16586) *"Runtime Governance for AI Agents: Policies on Paths"*, which proves that stateless evaluators miss multi-step attack chains that path-aware evaluators catch.

Microsoft Agent Governance Toolkit's `PolicyEvaluator` is single-rule, single-action. HELM's is path-conditioned. This is the distinction.

## Where path is carried

Each incoming decision carries a typed `SessionHistory` field. From [core/pkg/guardian/guardian.go:492](../../core/pkg/guardian/guardian.go):

```go
type DecisionRequest struct {
    Principal      string
    Action         string
    Resource       string
    Context        map[string]interface{}
    SessionHistory []SessionAction   // <-- path
    // ...
}
```

Before evaluation, the guardian plumbs `SessionHistory` into the `Context` map so that CEL and WASM policies see a normalized representation:

```go
// core/pkg/guardian/guardian.go:815-824 (condensed)
if len(req.SessionHistory) > 0 {
    req.Context["session_history"]      = req.SessionHistory
    req.Context["session_action_count"] = len(req.SessionHistory)
    for _, sa := range req.SessionHistory {
        // per-action summarization into context keys
    }
}
```

A `SessionAction` captures the minimum needed to reason about the path:

- `tool` — name of the action previously taken
- `outcome` — ALLOW / DENY / ESCALATE
- `timestamp` — wall-clock (informational, not relied on for ordering)
- `lamport_sequence` — the authoritative ordering

## How policies consume it

### CEL policies (v0.4.0)

CEL programs currently access session history through the `Context` map. Example — deny if the session has already exfiltrated a file and is now attempting a network call:

```cel
has(request.context.session_history) &&
request.context.session_history.exists(
    sa, sa.tool == "file_read" && sa.outcome == "ALLOW"
) &&
request.action == "network.post"
```

This exact pattern is what catches the multi-step exfiltration class (read-file → summarize → send-email) that AGT's stateless evaluator misses by construction.

### WASM policies (wazero)

WASM policies receive the same Context via the ABI binding at `core/pkg/policy/wasm/`. The host exports a `get_context_field(key)` ABI call; policies fetch `"session_history"` as a canonical JSON-serialized bytes slice and deserialize.

This is intentionally less ergonomic than a direct typed binding (see "Future work" below) but preserves determinism — the canonical JSON encoding is JCS, so WASM policy evaluation is byte-identical across platforms.

### Example multi-step attack catch

Session state before the decision:

```
t=1  alice  file_read   /etc/hosts   → ALLOW   (lamport=1)
t=2  alice  file_read   /etc/passwd  → ALLOW   (lamport=2)
t=3  alice  network.post api.example.com ← current decision
```

A path-aware policy denies this; a stateless policy (per-action) allows it because each step in isolation looks innocuous. The multi-step attack is expressed as a path predicate over the session, not a condition on the current action.

The TLA+ invariant `FailClosed` in [proofs/GuardianPipeline.tla](../../proofs/GuardianPipeline.tla) proves that if *any* gate (including the path-aware Threat gate) returns DENY, the decision is DENY. Path-aware policies riding on top of this invariant compose: a bundle that denies multi-step attacks never overrides to ALLOW.

## Why `Context` map rather than typed CEL binding

CEL supports typed extensions. We could add `request.session.tools_called()` as a first-class function. Why haven't we?

1. **Determinism wins over ergonomics**. The Context map carries a JSON-serializable representation whose canonical JCS form is the basis for receipt signing. A typed binding would require keeping the CEL type system and the JCS canonical form in sync across CEL/WASM/Rego runtimes — a real complexity tax.
2. **The shape of a typed binding is not settled**. Common patterns from customer deployments: "tools called in the last N actions", "actions since last approval", "actions targeting resource class X". The API should emerge from usage before being frozen.
3. **Single source of truth**. Anything policy programs can read, verifiers and auditors can reconstruct from `Context` — no hidden state. A typed API introduces a second channel which could drift.

## Future work

A typed `session` binding in CEL is on the Phase 5 roadmap. The expected API (subject to change):

```cel
// proposed v0.5+ syntax (not yet shipped)
session.tools_called.contains("file_read") &&
session.tools_called_in_last(5).contains("credential_read") &&
request.action == "network.post"
```

Implementation plan:
- Add a `SessionView` CEL extension type wrapping `[]SessionAction`.
- Preserve JCS canonicality by defining the extension's protobuf-like serialization in the TLA+ spec before shipping.
- Parallel WASM ABI addition: `session_tools_called_in_last(n)` host function.
- Golden fixtures in `tests/conformance/profile-v1/` covering the new binding.

Until that ships, the `request.context.session_history` pattern shown above is the supported path.

## Testing

Existing tests at [core/pkg/guardian/session_history_test.go](../../core/pkg/guardian/session_history_test.go) cover:

- Empty session history (no-op plumbing).
- Session history propagation into `req.Context["session_history"]`.
- `session_action_count` derivation.
- Path-aware denial through a policy bundle that reads session history.

The integration of path-aware evaluation with the 6-gate pipeline is covered by the crucible conformance suite under `test-l3`.

## References

- Guardian pipeline: [docs/architecture/guardian-pipeline.md](./guardian-pipeline.md)
- Policy composition (P0/P1/P2): [docs/research/policy-composition-proof.md](../research/policy-composition-proof.md)
- TLA+ formal invariants: [proofs/](../../proofs/)
- Academic basis: arXiv [2603.16586](https://arxiv.org/abs/2603.16586) (path-based policies), arXiv [2601.10440](https://arxiv.org/html/2601.10440) (adaptive policy learning from control flow)

---

*Part of the Phase 4 differentiation deliverables. Last updated 2026-04-15.*
