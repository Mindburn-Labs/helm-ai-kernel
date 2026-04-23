package signals

import "sync"

// DedupStore tracks seen idempotency keys to prevent duplicate signal processing.
type DedupStore interface {
	// HasSeen returns true if the idempotency key has been seen before.
	HasSeen(key string) bool

	// Record marks an idempotency key as seen.
	Record(key string) error
}

// InMemoryDedupStore is an in-memory implementation of DedupStore.
// Suitable for development and testing. Production should use Redis or Postgres.
type InMemoryDedupStore struct {
	mu   sync.RWMutex
	seen map[string]struct{}
}

// NewInMemoryDedupStore creates a new in-memory dedup store.
func NewInMemoryDedupStore() *InMemoryDedupStore {
	return &InMemoryDedupStore{
		seen: make(map[string]struct{}),
	}
}

// HasSeen returns true if the key has been recorded before.
func (s *InMemoryDedupStore) HasSeen(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.seen[key]
	return ok
}

// Record marks a key as seen.
func (s *InMemoryDedupStore) Record(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[key] = struct{}{}
	return nil
}
