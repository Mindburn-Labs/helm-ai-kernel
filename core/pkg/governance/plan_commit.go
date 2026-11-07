package governance

import (
	"sync"
	"time"
)

// PlanCommitController implements the approval-required workflow for
// high-risk effects (E3/E4). It blocks execution until a human approval
// is received or a timeout elapses.
//
// Workflow:
//  1. Guardian detects E3/E4 effect → calls SubmitPlan()
//  2. PlanCommitController stores the plan and its hash
//  3. External system (console, CLI) calls Approve() or Reject()
//  4. Guardian calls WaitForApproval() which blocks until decision or timeout
//  5. On approval → execution proceeds with ApprovalReceipt
//  6. On rejection or timeout → deny with APPROVAL_REQUIRED or APPROVAL_TIMEOUT
//
// Design invariants:
//   - Plans are identified by deterministic content hash
//   - All transitions are receipted
//   - Timeout results in automatic denial (fail-closed)
//   - Clock is injected for deterministic testing
type PlanCommitController struct {
	mu    sync.Mutex
	plans map[string]*pendingPlan
	clock func() time.Time
	after func(time.Duration) <-chan time.Time
}

type pendingPlan struct {
	Plan      *ExecutionPlan
	Hash      string
	Status    PlanStatus
	Decision  chan PlanDecision
	CreatedAt time.Time
}

// ExecutionPlan describes a proposed execution that requires approval.
type ExecutionPlan struct {
	PlanID      string         `json:"plan_id"`
	EffectType  string         `json:"effect_type"`
	EffectClass string         `json:"effect_class"`
	Principal   string         `json:"principal"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

// PlanRef is a reference to a submitted plan.
type PlanRef struct {
	PlanID   string `json:"plan_id"`
	PlanHash string `json:"plan_hash"`
}

// PlanStatus represents the state of a submitted plan.
type PlanStatus string

const (
	PlanStatusPending  PlanStatus = "PENDING"
	PlanStatusApproved PlanStatus = "APPROVED"
	PlanStatusRejected PlanStatus = "REJECTED"
	PlanStatusTimeout  PlanStatus = "TIMEOUT"
	PlanStatusAborted  PlanStatus = "ABORTED"
)

// PlanDecision is the approval/rejection decision for a plan.
type PlanDecision struct {
	Status    PlanStatus `json:"status"`
	Approver  string     `json:"approver,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	Timestamp time.Time  `json:"timestamp"`
}
