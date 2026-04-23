package tenants

import (
	"context"
	"fmt"
	"sync"
)

// TenantStore manages tenant lifecycle persistence.
type TenantStore interface {
	Create(ctx context.Context, tenant *Tenant) error
	Get(ctx context.Context, tenantID string) (*Tenant, error)
	List(ctx context.Context) ([]*Tenant, error)
	Update(ctx context.Context, tenant *Tenant) error
	GetLimits(ctx context.Context, tenantID string) (*TenantLimits, error)
	SetLimits(ctx context.Context, limits *TenantLimits) error
}

// InMemoryTenantStore is a thread-safe in-memory implementation of TenantStore.
type InMemoryTenantStore struct {
	mu      sync.RWMutex
	tenants map[string]*Tenant
	limits  map[string]*TenantLimits
}

// NewInMemoryTenantStore creates a new in-memory tenant store.
func NewInMemoryTenantStore() *InMemoryTenantStore {
	return &InMemoryTenantStore{
		tenants: make(map[string]*Tenant),
		limits:  make(map[string]*TenantLimits),
	}
}

func (s *InMemoryTenantStore) Create(_ context.Context, tenant *Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tenants[tenant.TenantID]; exists {
		return fmt.Errorf("tenant %s already exists", tenant.TenantID)
	}
	s.tenants[tenant.TenantID] = tenant
	return nil
}

func (s *InMemoryTenantStore) Get(_ context.Context, tenantID string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, fmt.Errorf("tenant %s not found", tenantID)
	}
	return t, nil
}

func (s *InMemoryTenantStore) List(_ context.Context) ([]*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		result = append(result, t)
	}
	return result, nil
}

func (s *InMemoryTenantStore) Update(_ context.Context, tenant *Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tenants[tenant.TenantID]; !exists {
		return fmt.Errorf("tenant %s not found", tenant.TenantID)
	}
	s.tenants[tenant.TenantID] = tenant
	return nil
}

func (s *InMemoryTenantStore) GetLimits(_ context.Context, tenantID string) (*TenantLimits, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.limits[tenantID]
	if !ok {
		return nil, fmt.Errorf("limits for tenant %s not found", tenantID)
	}
	return l, nil
}

func (s *InMemoryTenantStore) SetLimits(_ context.Context, limits *TenantLimits) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limits[limits.TenantID] = limits
	return nil
}
