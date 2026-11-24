package budget

import (
	"context"
	"sync"
)

// Storage defines lookup and write operations for budget data.
type Storage interface {
	Get(ctx context.Context, tenantID string) (*Budget, error)
	Set(ctx context.Context, budget *Budget) error
	Limits(ctx context.Context, tenantID string) (daily, monthly int64, err error)
	SetLimits(ctx context.Context, tenantID string, daily, monthly int64) error
}

// SimpleEnforcer preserves the type of the retired local budget enforcer.
type SimpleEnforcer struct {
	mu      sync.Mutex
	storage Storage
}
