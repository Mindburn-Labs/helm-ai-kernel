package skills

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrSkillNotFound is returned when a skill bundle is not in the store.
var ErrSkillNotFound = errors.New("skill not found")

// SkillStore defines the persistence interface for skill manifests.
type SkillStore interface {
	// Put inserts or replaces a skill manifest in the store.
	Put(ctx context.Context, manifest SkillManifest) error
	// Get retrieves a skill manifest by ID. Returns ErrSkillNotFound if absent.
	Get(ctx context.Context, id string) (*SkillManifest, error)
	// List returns all skill manifests in the store.
	List(ctx context.Context) ([]SkillManifest, error)
	// ListByState returns skill manifests matching the given lifecycle state.
	ListByState(ctx context.Context, state SkillBundleState) ([]SkillManifest, error)
	// Delete removes a skill manifest by ID. Returns ErrSkillNotFound if absent.
	Delete(ctx context.Context, id string) error
}

// InMemorySkillStore is a thread-safe in-memory implementation of SkillStore.
type InMemorySkillStore struct {
	mu       sync.RWMutex
	manifests map[string]SkillManifest
}

// NewInMemorySkillStore creates a new empty InMemorySkillStore.
func NewInMemorySkillStore() *InMemorySkillStore {
	return &InMemorySkillStore{
		manifests: make(map[string]SkillManifest),
	}
}

// Put inserts or replaces a skill manifest in the store.
func (s *InMemorySkillStore) Put(_ context.Context, manifest SkillManifest) error {
	if manifest.ID == "" {
		return fmt.Errorf("skill manifest ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.manifests[manifest.ID] = manifest
	return nil
}

// Get retrieves a skill manifest by ID.
func (s *InMemorySkillStore) Get(_ context.Context, id string) (*SkillManifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, ok := s.manifests[id]
	if !ok {
		return nil, fmt.Errorf("skill %q: %w", id, ErrSkillNotFound)
	}

	return &m, nil
}

// List returns all skill manifests in the store.
func (s *InMemorySkillStore) List(_ context.Context) ([]SkillManifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]SkillManifest, 0, len(s.manifests))
	for _, m := range s.manifests {
		result = append(result, m)
	}
	return result, nil
}

// ListByState returns skill manifests matching the given lifecycle state.
func (s *InMemorySkillStore) ListByState(_ context.Context, state SkillBundleState) ([]SkillManifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []SkillManifest
	for _, m := range s.manifests {
		if m.State == state {
			result = append(result, m)
		}
	}
	return result, nil
}

// Delete removes a skill manifest by ID.
func (s *InMemorySkillStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.manifests[id]; !ok {
		return fmt.Errorf("skill %q: %w", id, ErrSkillNotFound)
	}

	delete(s.manifests, id)
	return nil
}
