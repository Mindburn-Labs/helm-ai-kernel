package executor

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// OutboxRecord represents an intent to execute an effect.
type OutboxRecord struct {
	ID        string                               `json:"id"`
	Effect    *contracts.Effect                    `json:"effect"`
	Intent    *contracts.AuthorizedExecutionIntent `json:"intent"`
	Scheduled time.Time                            `json:"scheduled"`
	Status    string                               `json:"status"` // PENDING, DONE, FAILED
}

// OutboxStore defines the transactional persistence layer for effects.
type OutboxStore interface {
	// Schedule persists the intent to execute.
	Schedule(ctx context.Context, effect *contracts.Effect, intent *contracts.AuthorizedExecutionIntent) error
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

// causalReceiptAppender is an optional capability implemented by durable
// receipt stores. Keeping it separate preserves the minimal ReceiptStore
// contract used by legacy adapters and test doubles.
type causalReceiptAppender interface {
	AppendCausal(ctx context.Context, sessionID string, build func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error)) error
}

// tenantScopedCausalReceiptAppender keeps tenant isolation in a store-only
// chain key. SessionID remains the external value in the signed receipt.
type tenantScopedCausalReceiptAppender interface {
	AppendCausalScoped(ctx context.Context, tenantID, sessionID string, build func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error)) error
}

// causalReceiptAppendPreflighter detects a known-unappendable durable session
// before external dispatch. It is not a causal-position reservation.
type causalReceiptAppendPreflighter interface {
	PreflightCausalAppend(ctx context.Context, sessionID string) error
}

type tenantScopedCausalReceiptAppendPreflighter interface {
	PreflightCausalAppendScoped(ctx context.Context, tenantID, sessionID string) error
}

// tenantScopedIdempotencyReader resolves an existing execution only inside the
// authenticated tenant. It is deliberately additive so legacy ReceiptStore
// adapters remain usable for unscoped execution paths.
type tenantScopedIdempotencyReader interface {
	GetByDecisionIDForTenant(ctx context.Context, tenantID, decisionID string) (*contracts.Receipt, error)
}

type receiptTimestampNormalizer interface {
	NormalizeReceiptTimestamp(time.Time) time.Time
}

// MCPClient defines the interface for interacting with the Managed Capability Platform.
// Kept for backward compatibility if needed, but ToolDriver is preferred.
type MCPClient interface {
	Call(tool string, params map[string]any) (any, error)
}
