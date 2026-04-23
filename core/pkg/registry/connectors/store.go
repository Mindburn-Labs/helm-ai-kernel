package connectors

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrConnectorNotFound is returned when a connector release is not in the store.
var ErrConnectorNotFound = errors.New("connector not found")

// ConnectorStore defines the persistence interface for connector releases.
type ConnectorStore interface {
	// Put inserts or replaces a connector release in the store.
	Put(ctx context.Context, release ConnectorRelease) error
	// Get retrieves a connector release by ID. Returns ErrConnectorNotFound if absent.
	Get(ctx context.Context, id string) (*ConnectorRelease, error)
	// List returns all connector releases in the store.
	List(ctx context.Context) ([]ConnectorRelease, error)
	// ListByState returns connector releases matching the given lifecycle state.
	ListByState(ctx context.Context, state ConnectorReleaseState) ([]ConnectorRelease, error)
	// Delete removes a connector release by ID. Returns ErrConnectorNotFound if absent.
	Delete(ctx context.Context, id string) error
}

// InMemoryConnectorStore is a thread-safe in-memory implementation of ConnectorStore.
type InMemoryConnectorStore struct {
	mu       sync.RWMutex
	releases map[string]ConnectorRelease
}

// NewInMemoryConnectorStore creates a new empty InMemoryConnectorStore.
func NewInMemoryConnectorStore() *InMemoryConnectorStore {
	return &InMemoryConnectorStore{
		releases: make(map[string]ConnectorRelease),
	}
}

// Put inserts or replaces a connector release in the store.
func (s *InMemoryConnectorStore) Put(_ context.Context, release ConnectorRelease) error {
	if release.ConnectorID == "" {
		return fmt.Errorf("connector release connector_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.releases[release.ConnectorID] = release
	return nil
}

// Get retrieves a connector release by ID.
func (s *InMemoryConnectorStore) Get(_ context.Context, id string) (*ConnectorRelease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.releases[id]
	if !ok {
		return nil, fmt.Errorf("connector %q: %w", id, ErrConnectorNotFound)
	}

	return &r, nil
}

// List returns all connector releases in the store.
func (s *InMemoryConnectorStore) List(_ context.Context) ([]ConnectorRelease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]ConnectorRelease, 0, len(s.releases))
	for _, r := range s.releases {
		result = append(result, r)
	}
	return result, nil
}

// ListByState returns connector releases matching the given lifecycle state.
func (s *InMemoryConnectorStore) ListByState(_ context.Context, state ConnectorReleaseState) ([]ConnectorRelease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []ConnectorRelease
	for _, r := range s.releases {
		if r.State == state {
			result = append(result, r)
		}
	}
	return result, nil
}

// Delete removes a connector release by ID.
func (s *InMemoryConnectorStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.releases[id]; !ok {
		return fmt.Errorf("connector %q: %w", id, ErrConnectorNotFound)
	}

	delete(s.releases, id)
	return nil
}
