package obligation

import "time"

// ObligationStatus defines the lifecycle state of an obligation.
type ObligationStatus string

const (
	StatusPending   ObligationStatus = "PENDING"
	StatusActive    ObligationStatus = "ACTIVE"
	StatusSatisfied ObligationStatus = "SATISFIED"
	StatusFailed    ObligationStatus = "FAILED"
	StatusEscalated ObligationStatus = "ESCALATED"
)

// Obligation represents a durable unit of work.
// Schema: schemas/business/obligation.schema.json
type Obligation struct {
	ID            string           `json:"id"`
	GoalSpec      string           `json:"goal_spec"` // Simplified for now
	Status        ObligationStatus `json:"status"`
	LeaseHolder   string           `json:"lease_holder,omitempty"`
	LeaseExpiry   time.Time        `json:"lease_expiry,omitempty"`
	Attempts      []Attempt        `json:"attempts"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
	ResultReceipt string           `json:"result_receipt,omitempty"`
}

// Attempt records an execution try.
type Attempt struct {
	AttemptID int       `json:"attempt_id"`
	WorkerID  string    `json:"worker_id"`
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
}
