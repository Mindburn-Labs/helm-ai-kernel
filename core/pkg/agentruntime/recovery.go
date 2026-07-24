package agentruntime

import (
	"fmt"
	"sort"
)

// RecoveryActionKind classifies one step of crash recovery. See the
// package documentation for the normative recovery matrix.
type RecoveryActionKind string

const (
	// ActionCloseInterruptedModelCall appends
	// model_call_failed{class:"interrupted", retryable:true} for the open
	// model call. The call already consumed budget when it was requested.
	ActionCloseInterruptedModelCall RecoveryActionKind = "close_interrupted_model_call"
	// ActionReissueModelCall appends a fresh model_call_requested for the
	// next call index; it counts against the model-call budget by
	// construction.
	ActionReissueModelCall RecoveryActionKind = "reissue_model_call"
	// ActionMarkToolIndeterminate appends
	// tool_result{status:"indeterminate"} for an interrupted SYNC tool
	// invocation. The tool may have executed; it is NEVER re-executed.
	ActionMarkToolIndeterminate RecoveryActionKind = "mark_tool_indeterminate"
	// ActionLeaveAsyncPending records that an ASYNC invocation stays open;
	// no event is fabricated for it.
	ActionLeaveAsyncPending RecoveryActionKind = "leave_async_pending"
	// ActionAppendSuspensionSnapshot appends a turn_suspended event when
	// pending async work or outstanding permissions exist but the log has
	// no suspension snapshot.
	ActionAppendSuspensionSnapshot RecoveryActionKind = "append_suspension_snapshot"
)

// RecoveryAction is one deterministic recovery step. Actions are produced
// in application order by PlanRecovery.
type RecoveryAction struct {
	Kind       RecoveryActionKind `json:"kind"`
	ToolCallID string             `json:"tool_call_id,omitempty"`
	// Reason documents the matrix cell that produced this action.
	Reason string `json:"reason"`
}

// PlanRecovery computes the recovery actions for a turn log after a
// crash, purely from the log. It is the executable form of the documented
// crash-recovery matrix:
//
//   - open model call            -> close as interrupted + re-issue (budget charged)
//   - open SYNC tool invocation  -> indeterminate result, never re-executed
//   - open ASYNC tool invocation -> stays pending
//   - pending work without a suspension snapshot -> append turn_suspended
//   - terminal turn              -> no actions
//   - corrupt log                -> error (fail loud; never salvage)
//
// The returned actions are advisory plans; callers apply them by
// constructing the corresponding events and appending them through
// Store.Append, so every recovery write also passes the reducer gate.
func PlanRecovery(events []Event) ([]RecoveryAction, error) {
	state, err := ReduceEvents(events)
	if err != nil {
		return nil, fmt.Errorf("agentruntime: cannot plan recovery for corrupt log: %w", err)
	}
	if state == nil {
		return nil, fmt.Errorf("agentruntime: cannot plan recovery for empty log")
	}
	if state.Terminal() {
		return nil, nil
	}

	var actions []RecoveryAction

	if state.ModelCallOpen {
		actions = append(actions, RecoveryAction{
			Kind:   ActionCloseInterruptedModelCall,
			Reason: fmt.Sprintf("model call %d was open at crash; close as interrupted (budget already charged at request)", state.OpenModelCallIndex),
		})
		actions = append(actions, RecoveryAction{
			Kind:   ActionReissueModelCall,
			Reason: "re-issue the model call as the next call index; it counts against the budget",
		})
	}

	// Interrupted sync tools: may have executed -> indeterminate, never
	// re-executed. Sorted for determinism.
	var syncIDs []string
	for id, inv := range state.OpenInvocations {
		if inv.Mode == ModeSync {
			syncIDs = append(syncIDs, id)
		}
	}
	sort.Strings(syncIDs)
	for _, id := range syncIDs {
		actions = append(actions, RecoveryAction{
			Kind:       ActionMarkToolIndeterminate,
			ToolCallID: id,
			Reason:     "sync tool invocation was open at crash; outcome unknown (may have executed); never re-executed",
		})
	}

	asyncIDs := state.pendingAsyncToolCallIDs()
	for _, id := range asyncIDs {
		actions = append(actions, RecoveryAction{
			Kind:       ActionLeaveAsyncPending,
			ToolCallID: id,
			Reason:     "async tool invocation was open at crash; it stays pending and no result is fabricated",
		})
	}

	if state.Status != StatusSuspended &&
		(len(asyncIDs) > 0 || len(state.OutstandingPermissions) > 0) {
		actions = append(actions, RecoveryAction{
			Kind:   ActionAppendSuspensionSnapshot,
			Reason: "pending async work or outstanding permissions exist without a durable suspension snapshot",
		})
	}

	return actions, nil
}
