package rbac

import (
	"context"
	"fmt"
	"sync"
)

// RBACStore manages roles and role bindings.
type RBACStore interface {
	CreateRole(ctx context.Context, role *Role) error
	GetRole(ctx context.Context, roleID string) (*Role, error)
	ListRoles(ctx context.Context, tenantID string) ([]*Role, error)
	CreateBinding(ctx context.Context, binding *RoleBinding) error
	ListBindings(ctx context.Context, principalID, tenantID string) ([]*RoleBinding, error)
	RemoveBinding(ctx context.Context, bindingID string) error
}

// InMemoryRBACStore is a thread-safe in-memory implementation of RBACStore.
type InMemoryRBACStore struct {
	mu       sync.RWMutex
	roles    map[string]*Role        // roleID -> Role
	bindings map[string]*RoleBinding // bindingID -> RoleBinding
}

// NewInMemoryRBACStore creates a new in-memory RBAC store pre-loaded with built-in roles.
func NewInMemoryRBACStore() *InMemoryRBACStore {
	s := &InMemoryRBACStore{
		roles:    make(map[string]*Role),
		bindings: make(map[string]*RoleBinding),
	}
	// Seed built-in roles.
	for _, r := range BuiltinRoles() {
		role := r // copy
		s.roles[role.RoleID] = &role
	}
	return s
}

func (s *InMemoryRBACStore) CreateRole(_ context.Context, role *Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.roles[role.RoleID]; exists {
		return fmt.Errorf("role %s already exists", role.RoleID)
	}
	s.roles[role.RoleID] = role
	return nil
}

func (s *InMemoryRBACStore) GetRole(_ context.Context, roleID string) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[roleID]
	if !ok {
		return nil, fmt.Errorf("role %s not found", roleID)
	}
	return r, nil
}

func (s *InMemoryRBACStore) ListRoles(_ context.Context, tenantID string) ([]*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Role
	for _, r := range s.roles {
		// Include built-in roles (no tenant) and tenant-specific roles.
		if r.IsBuiltin || r.TenantID == tenantID {
			result = append(result, r)
		}
	}
	return result, nil
}

func (s *InMemoryRBACStore) CreateBinding(_ context.Context, binding *RoleBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.bindings[binding.BindingID]; exists {
		return fmt.Errorf("binding %s already exists", binding.BindingID)
	}
	s.bindings[binding.BindingID] = binding
	return nil
}

func (s *InMemoryRBACStore) ListBindings(_ context.Context, principalID, tenantID string) ([]*RoleBinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*RoleBinding
	for _, b := range s.bindings {
		if b.PrincipalID == principalID && b.TenantID == tenantID {
			result = append(result, b)
		}
	}
	return result, nil
}

func (s *InMemoryRBACStore) RemoveBinding(_ context.Context, bindingID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.bindings[bindingID]; !exists {
		return fmt.Errorf("binding %s not found", bindingID)
	}
	delete(s.bindings, bindingID)
	return nil
}
