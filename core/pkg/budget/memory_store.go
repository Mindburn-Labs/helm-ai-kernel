package budget

import (
	"context"
	"sync"
)

// MemoryStorage implements Storage in memory.
// Thread-safe via RWMutex.
type MemoryStorage struct {
	mu      sync.RWMutex
	budgets map[string]*Budget
	limits  map[string]struct{ d, m int64 }
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		budgets: make(map[string]*Budget),
		limits:  make(map[string]struct{ d, m int64 }),
	}
}

func (s *MemoryStorage) Get(ctx context.Context, tenantID string) (*Budget, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if b, ok := s.budgets[tenantID]; ok {
		// return copy to avoid race on mutation outside lock
		val := *b
		return &val, nil
	}
	return nil, nil // Not found is not an error, returns nil
}

func (s *MemoryStorage) Set(ctx context.Context, budget *Budget) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	val := *budget
	s.budgets[budget.TenantID] = &val
	return nil
}

func (s *MemoryStorage) Limits(ctx context.Context, tenantID string) (int64, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if l, ok := s.limits[tenantID]; ok {
		return l.d, l.m, nil
	}
	// Defaults if not set: $10/day, $500/month
	return 1000, 50000, nil
}

func (s *MemoryStorage) SetLimits(ctx context.Context, tenantID string, daily, monthly int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limits[tenantID] = struct{ d, m int64 }{daily, monthly}
	return nil
}
