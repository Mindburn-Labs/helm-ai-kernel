package ledger

import (
	"errors"
	"time"
)

// ErrNotFound is returned when a ledger entry is not found.
var ErrNotFound = errors.New("not found")

// State represents the lifecycle of an ledger.
type State string

const (
	StatePending   State = "PENDING"
	StatePlanning  State = "PLANNING"
	StatePlanned   State = "PLANNED"
	StateExecuting State = "EXECUTING"
	StateCompleted State = "COMPLETED"
	StateFailed    State = "FAILED"
	StateBlocked   State = "BLOCKED"
)

// Obligation represents a durable intent in the system.
type Obligation struct {
	ID             string    `json:"id"`
	IdempotencyKey string    `json:"idempotency_key"`
	Intent         string    `json:"intent"`
	State          State     `json:"state"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`

	// PlanAttemptID links to the active plan (Plane 2)
	PlanAttemptID string `json:"plan_attempt_id,omitempty"`

	// Lease metadata for worker coordination
	LeasedBy    string    `json:"leased_by,omitempty"`
	LeasedUntil time.Time `json:"leased_until,omitempty"`

	// Deployment & Retry Metadata
	RetryCount int      `json:"retry_count"`
	ErrorLog   []string `json:"error_log,omitempty"`

	// Integrity (GAP-31)
	Hash         string `json:"hash,omitempty"`
	PreviousHash string `json:"previous_hash,omitempty"`

	// Context (GAP-33)
	Metadata map[string]any `json:"metadata,omitempty"`

	// Multi-Tenancy (Gap 12)
	TenantID string `json:"tenant_id"`
}
