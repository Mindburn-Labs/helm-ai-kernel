package ledger

import (
	"context"
	"time"
)

// Ledger is the durable interface for Obligation management.
type Ledger interface {
	// Create persists a new ledger. ID provided or generated.
	Create(ctx context.Context, obl Obligation) error

	// Get retrieves an obligation by ID.
	Get(ctx context.Context, id string) (Obligation, error)

	// AcquireLease attempts to lock an obligation for work.
	AcquireLease(ctx context.Context, id, workerID string, duration time.Duration) (Obligation, error)

	// UpdateState transitions the obligation to a new state (with optimistic locking via lease).
	UpdateState(ctx context.Context, id string, newState State, details map[string]any) error

	// ListPending retrieves obligations that are pending or retrying.
	ListPending(ctx context.Context) ([]Obligation, error)

	// ListAll retrieves all obligations (for observability).
	ListAll(ctx context.Context) ([]Obligation, error)
}
