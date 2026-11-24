package governance

import (
	"sync"
	"time"
)

// PlanCommitController retains the pending-plan state of the former controller.
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
