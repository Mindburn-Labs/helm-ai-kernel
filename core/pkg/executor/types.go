package executor

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// OutboxRecord represents an intent to execute an effect.
type OutboxRecord struct {
	ID        string                    `json:"id"`
	Effect    *contracts.Effect         `json:"effect"`
	Decision  *contracts.DecisionRecord `json:"decision"`
	Scheduled time.Time                 `json:"scheduled"`
	Status    string                    `json:"status"` // PENDING, DONE, FAILED
}

// OutboxStore defines the transactional persistence layer for effects.
type OutboxStore interface {
	// Schedule persists the intent to execute.
	Schedule(ctx context.Context, effect *contracts.Effect, decision *contracts.DecisionRecord) error
	// GetPending returns all scheduled but not yet executed records.
	GetPending(ctx context.Context) ([]*OutboxRecord, error)
	// MarkDone marks a record as executed (idempotency key).
	MarkDone(ctx context.Context, id string) error
}

// ReceiptStore defines the interface for persisting execution receipts.
type ReceiptStore interface {
	Get(ctx context.Context, decisionID string) (*contracts.Receipt, error)
	Store(ctx context.Context, receipt *contracts.Receipt) error
	// GetLastForSession returns the most recent receipt for a given session (for causal DAG chaining).
	GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error)
}

// MCPClient defines the interface for interacting with the Managed Capability Platform.
// Kept for backward compatibility if needed, but ToolDriver is preferred.
type MCPClient interface {
	Call(tool string, params map[string]any) (any, error)
}
