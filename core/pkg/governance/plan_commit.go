package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// NewPlanCommitController creates a new PlanCommitController.
func NewPlanCommitController() *PlanCommitController {
	return &PlanCommitController{
		plans: make(map[string]*pendingPlan),
		clock: time.Now,
		after: time.After,
	}
}

// WithClock overrides the clock for deterministic testing.
func (pc *PlanCommitController) WithClock(clock func() time.Time) *PlanCommitController {
	pc.clock = clock
	return pc
}

// WithAfter overrides the timeout channel factory for deterministic testing.
func (pc *PlanCommitController) WithAfter(after func(time.Duration) <-chan time.Time) *PlanCommitController {
	pc.after = after
	return pc
}

// SubmitPlan registers an execution plan for approval.
// Returns a PlanRef that can be used to approve, reject, or wait.
func (pc *PlanCommitController) SubmitPlan(plan *ExecutionPlan) (*PlanRef, error) {
	if plan == nil {
		return nil, fmt.Errorf("plan must not be nil")
	}
	if plan.PlanID == "" {
		return nil, fmt.Errorf("plan must have a PlanID")
	}

	hash := hashPlan(plan)

	pc.mu.Lock()
	defer pc.mu.Unlock()

	if _, exists := pc.plans[plan.PlanID]; exists {
		return nil, fmt.Errorf("plan %s already submitted", plan.PlanID)
	}

	pp := &pendingPlan{
		Plan:      plan,
		Hash:      hash,
		Status:    PlanStatusPending,
		Decision:  make(chan PlanDecision, 1),
		CreatedAt: pc.clock(),
	}
	pc.plans[plan.PlanID] = pp

	return &PlanRef{
		PlanID:   plan.PlanID,
		PlanHash: hash,
	}, nil
}

// WaitForApproval blocks until the plan is approved/rejected or timeout elapses.
// Returns the decision. On timeout, returns a decision with PlanStatusTimeout.
func (pc *PlanCommitController) WaitForApproval(ref PlanRef, timeout time.Duration) (*PlanDecision, error) {
	pc.mu.Lock()
	pp, exists := pc.plans[ref.PlanID]
	if !exists {
		pc.mu.Unlock()
		return nil, fmt.Errorf("plan %s not found", ref.PlanID)
	}
	if pp.Hash != ref.PlanHash {
		pc.mu.Unlock()
		return nil, fmt.Errorf("plan hash mismatch for %s", ref.PlanID)
	}
	ch := pp.Decision
	pc.mu.Unlock()

	select {
	case decision := <-ch:
		return &decision, nil
	case <-pc.after(timeout):
		pc.mu.Lock()
		pp.Status = PlanStatusTimeout
		pc.mu.Unlock()
		return &PlanDecision{
			Status:    PlanStatusTimeout,
			Reason:    "approval timeout exceeded",
			Timestamp: pc.clock(),
		}, nil
	}
}

// Approve approves a pending plan.
func (pc *PlanCommitController) Approve(planID, approver string) error {
	pc.mu.Lock()
	pp, exists := pc.plans[planID]
	if !exists {
		pc.mu.Unlock()
		return fmt.Errorf("plan %s not found", planID)
	}
	if pp.Status != PlanStatusPending {
		pc.mu.Unlock()
		return fmt.Errorf("plan %s is not pending (status: %s)", planID, pp.Status)
	}
	pp.Status = PlanStatusApproved
	pc.mu.Unlock()

	pp.Decision <- PlanDecision{
		Status:    PlanStatusApproved,
		Approver:  approver,
		Timestamp: pc.clock(),
	}
	return nil
}

// Reject rejects a pending plan.
func (pc *PlanCommitController) Reject(planID, approver, reason string) error {
	pc.mu.Lock()
	pp, exists := pc.plans[planID]
	if !exists {
		pc.mu.Unlock()
		return fmt.Errorf("plan %s not found", planID)
	}
	if pp.Status != PlanStatusPending {
		pc.mu.Unlock()
		return fmt.Errorf("plan %s is not pending (status: %s)", planID, pp.Status)
	}
	pp.Status = PlanStatusRejected
	pc.mu.Unlock()

	pp.Decision <- PlanDecision{
		Status:    PlanStatusRejected,
		Approver:  approver,
		Reason:    reason,
		Timestamp: pc.clock(),
	}
	return nil
}

// Abort cancels a pending plan without approval or rejection.
func (pc *PlanCommitController) Abort(planID string) error {
	pc.mu.Lock()
	pp, exists := pc.plans[planID]
	if !exists {
		pc.mu.Unlock()
		return fmt.Errorf("plan %s not found", planID)
	}
	if pp.Status != PlanStatusPending {
		pc.mu.Unlock()
		return fmt.Errorf("plan %s is not pending (status: %s)", planID, pp.Status)
	}
	pp.Status = PlanStatusAborted
	pc.mu.Unlock()

	pp.Decision <- PlanDecision{
		Status:    PlanStatusAborted,
		Reason:    "plan aborted",
		Timestamp: pc.clock(),
	}
	return nil
}

// PendingCount returns the number of plans awaiting approval.
func (pc *PlanCommitController) PendingCount() int {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	count := 0
	for _, pp := range pc.plans {
		if pp.Status == PlanStatusPending {
			count++
		}
	}
	return count
}

// hashPlan computes a deterministic SHA-256 hash of an ExecutionPlan.
func hashPlan(plan *ExecutionPlan) string {
	data, _ := json.Marshal(plan)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
