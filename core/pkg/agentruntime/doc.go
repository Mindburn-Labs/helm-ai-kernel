// Package agentruntime is the durable spine of HELM's first-party agent
// loop runtime: a versioned turn-event log, a pure reducer that is the sole
// append gate, hash-chained integrity anchored into the kernel's existing
// transparency log, and deterministic recomposition of model requests.
//
// # Design provenance
//
// The mechanism architecture — reducer-as-append-gate over an append-only
// turn log, reference-based durable model requests, and a documented
// crash-recovery matrix — is adapted from the Apache-2.0 Rowboat project
// (github.com/rowboatlabs/rowboat; apps/x/packages/core/src/runtime and
// packages/shared/src/turns.ts). This package is an original Go
// implementation: no Rowboat code, comments, prose, or assets are copied.
// HELM-native differences are deliberate:
//
//   - Every event is hash-chained (prev_hash over RFC 8785 canonical JSON,
//     via core/pkg/canonicalize) and can be anchored as a leaf in the
//     kernel's existing RFC 6962 transparency log (core/pkg/translog).
//     Rowboat's turn log is unsigned, unchained JSONL; here, forged or
//     reordered history fails verification loudly.
//   - Permission events are advisory records only. They reference kernel
//     verdicts (verdict_ref) and never carry authority. The Kernel remains
//     the sole decision authority for governed effects.
//   - Storage-layer failures are typed (InfraError) and are never
//     recordable as tool errors or turn failures.
//
// # The reducer is the sole append gate
//
// ReduceEvents / ValidateAppend define both what a valid history is and
// what may be written next. Store.Append folds the existing log plus the
// candidate events through the reducer before any byte touches disk; an
// event the reducer rejects can never become durable. Illegal states are
// unrepresentable in storage, not merely in memory. Reads re-verify the
// full chain and re-run the reducer: a tampered or corrupt log fails
// loudly. There is no repair path and no salvage heuristic.
//
// # Crash-recovery semantics (normative)
//
// Recovery is a documented behavior matrix, implemented by the pure
// function PlanRecovery and applied by callers through Store.Append:
//
//   - Interrupted model call (log ends with an open model_call_requested):
//     close it with model_call_failed{class:"interrupted", retryable:true},
//     then re-issue the model call as a new model_call_requested. The
//     re-issue consumes budget by construction, because the interrupted
//     call already incremented the requested-call count.
//   - Interrupted SYNC tool invocation (open tool_invocation_requested with
//     mode "sync"): the tool may have executed. It is closed with
//     tool_result{status:"indeterminate"} and is NEVER re-executed.
//   - Interrupted ASYNC tool invocation (mode "async"): stays pending. No
//     result is fabricated. If pending async work or outstanding
//     permissions exist and no suspension snapshot was recorded, a
//     turn_suspended event is appended reflecting the exact pending set.
//   - Outstanding permissions at crash: remain outstanding; they are part
//     of the suspension snapshot.
//   - Infrastructure write failure (InfraError from Store.Append) is NOT a
//     tool error and NOT a turn failure. It must never be recorded as
//     tool_result or turn_failed. A turn whose log is physically corrupt is
//     bricked: it fails verification loudly and may only be abandoned, not
//     salvaged.
//   - A terminal turn (completed/failed/cancelled) accepts no further
//     events and requires no recovery.
//
// # Reference-based durable model requests
//
// model_call_requested stores no message payload — only ordered references
// ("input", "assistant:<callIndex>", "tool_result:<toolCallID>"), the model
// parameters, and the tool snapshot hash. ComposeRequest deterministically
// resolves those references against the durable log and reproduces the
// exact canonical request bytes. Byte-stability is a deliberate property
// (prompt-prefix-cache economics) and is pinned by golden tests.
package agentruntime
