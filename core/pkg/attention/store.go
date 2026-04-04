package attention

import (
	"context"
	"fmt"
	"sync"
)

// WatchlistStore persists and queries watches.
type WatchlistStore interface {
	// Add persists a new watch.
	Add(ctx context.Context, watch *Watch) error

	// Remove deletes a watch by ID.
	Remove(ctx context.Context, watchID string) error

	// List returns all watches.
	List(ctx context.Context) ([]*Watch, error)

	// ByEntity returns watches that match the given entity type and ID.
	ByEntity(ctx context.Context, entityType, entityID string) ([]*Watch, error)
}

// InMemoryWatchlistStore is an in-memory implementation of WatchlistStore for
// testing and lightweight deployments.
type InMemoryWatchlistStore struct {
	mu      sync.RWMutex
	watches map[string]*Watch
}

// NewInMemoryWatchlistStore creates a new in-memory watchlist store.
func NewInMemoryWatchlistStore() *InMemoryWatchlistStore {
	return &InMemoryWatchlistStore{
		watches: make(map[string]*Watch),
	}
}

// Add persists a new watch. Returns an error if a watch with the same ID already exists.
func (s *InMemoryWatchlistStore) Add(_ context.Context, watch *Watch) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.watches[watch.WatchID]; exists {
		return fmt.Errorf("watch %q already exists", watch.WatchID)
	}

	s.watches[watch.WatchID] = watch
	return nil
}

// Remove deletes a watch by ID. Returns an error if the watch does not exist.
func (s *InMemoryWatchlistStore) Remove(_ context.Context, watchID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.watches[watchID]; !exists {
		return fmt.Errorf("watch %q not found", watchID)
	}

	delete(s.watches, watchID)
	return nil
}

// List returns all watches in the store.
func (s *InMemoryWatchlistStore) List(_ context.Context) ([]*Watch, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Watch, 0, len(s.watches))
	for _, w := range s.watches {
		result = append(result, w)
	}
	return result, nil
}

// ByEntity returns watches whose Type matches entityType (as a WatchType)
// and whose EntityID matches entityID.
func (s *InMemoryWatchlistStore) ByEntity(_ context.Context, entityType, entityID string) ([]*Watch, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Watch
	wt := WatchType(entityType)
	for _, w := range s.watches {
		if w.Type == wt && w.EntityID == entityID {
			result = append(result, w)
		}
	}
	return result, nil
}
