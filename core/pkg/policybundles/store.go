package policybundles

import (
	"context"
	"fmt"
	"sync"
)

// BundleStore manages policy bundle persistence.
type BundleStore interface {
	Create(ctx context.Context, bundle *PolicyBundle) error
	Get(ctx context.Context, bundleID string) (*PolicyBundle, error)
	List(ctx context.Context, jurisdiction string) ([]*PolicyBundle, error)
	Update(ctx context.Context, bundle *PolicyBundle) error
	CreateAssignment(ctx context.Context, assignment *BundleAssignment) error
	ListAssignments(ctx context.Context, tenantID string) ([]*BundleAssignment, error)
	RemoveAssignment(ctx context.Context, assignmentID string) error
}

// InMemoryBundleStore is a thread-safe in-memory implementation of BundleStore.
type InMemoryBundleStore struct {
	mu          sync.RWMutex
	bundles     map[string]*PolicyBundle
	assignments map[string]*BundleAssignment
}

// NewInMemoryBundleStore creates a new in-memory bundle store.
func NewInMemoryBundleStore() *InMemoryBundleStore {
	return &InMemoryBundleStore{
		bundles:     make(map[string]*PolicyBundle),
		assignments: make(map[string]*BundleAssignment),
	}
}

func (s *InMemoryBundleStore) Create(_ context.Context, bundle *PolicyBundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.bundles[bundle.BundleID]; exists {
		return fmt.Errorf("bundle %s already exists", bundle.BundleID)
	}
	s.bundles[bundle.BundleID] = bundle
	return nil
}

func (s *InMemoryBundleStore) Get(_ context.Context, bundleID string) (*PolicyBundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.bundles[bundleID]
	if !ok {
		return nil, fmt.Errorf("bundle %s not found", bundleID)
	}
	return b, nil
}

func (s *InMemoryBundleStore) List(_ context.Context, jurisdiction string) ([]*PolicyBundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*PolicyBundle
	for _, b := range s.bundles {
		if jurisdiction == "" || b.Jurisdiction == jurisdiction {
			result = append(result, b)
		}
	}
	return result, nil
}

func (s *InMemoryBundleStore) Update(_ context.Context, bundle *PolicyBundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.bundles[bundle.BundleID]; !exists {
		return fmt.Errorf("bundle %s not found", bundle.BundleID)
	}
	s.bundles[bundle.BundleID] = bundle
	return nil
}

func (s *InMemoryBundleStore) CreateAssignment(_ context.Context, assignment *BundleAssignment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.assignments[assignment.AssignmentID]; exists {
		return fmt.Errorf("assignment %s already exists", assignment.AssignmentID)
	}
	s.assignments[assignment.AssignmentID] = assignment
	return nil
}

func (s *InMemoryBundleStore) ListAssignments(_ context.Context, tenantID string) ([]*BundleAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*BundleAssignment
	for _, a := range s.assignments {
		if a.TenantID == tenantID {
			result = append(result, a)
		}
	}
	return result, nil
}

func (s *InMemoryBundleStore) RemoveAssignment(_ context.Context, assignmentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.assignments[assignmentID]; !exists {
		return fmt.Errorf("assignment %s not found", assignmentID)
	}
	delete(s.assignments, assignmentID)
	return nil
}
