package budget

import (
	"context"
	"sync"
)

// Storage handles persistence of budget data.
// In a real implementation, this would be a Postgres/Redis backing.
type Storage interface {
	Get(ctx context.Context, tenantID string) (*Budget, error)
	Set(ctx context.Context, budget *Budget) error
	Limits(ctx context.Context, tenantID string) (daily, monthly int64, err error)
	SetLimits(ctx context.Context, tenantID string, daily, monthly int64) error
}

// SimpleEnforcer implements fail-closed budget enforcement.
// NOTE: For single-instance deployments, a local mutex serializes check-and-update.
// For distributed deployments, use a storage backend with atomic compare-and-swap
// (e.g., PostgreSQL advisory locks or Redis WATCH/MULTI).
type SimpleEnforcer struct {
	mu      sync.Mutex
	storage Storage
}
