package memory

import (
	"fmt"
	"sync"
)

// InMemoryStore is a production-grade in-memory implementation of MemoryStore.
// For production deployments, replace with PostgresStore.
type InMemoryStore struct {
	mu      sync.RWMutex
	entries map[string]*MemoryEntry // entryID → entry
}

// NewInMemoryStore creates a new in-memory governed knowledge store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		entries: make(map[string]*MemoryEntry),
	}
}

func (s *InMemoryStore) Get(entryID string) (*MemoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[entryID]
	if !ok {
		return nil, fmt.Errorf("memory entry %s not found", entryID)
	}
	cp := *e
	return &cp, nil
}

func (s *InMemoryStore) Put(entry MemoryEntry) error {
	if entry.EntryID == "" {
		return fmt.Errorf("memory entry requires entry_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[entry.EntryID] = &entry
	return nil
}

func (s *InMemoryStore) Delete(entryID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[entryID]; !ok {
		return fmt.Errorf("memory entry %s not found", entryID)
	}
	delete(s.entries, entryID)
	return nil
}

func (s *InMemoryStore) List(tier MemoryTier, namespace string) ([]MemoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []MemoryEntry
	for _, e := range s.entries {
		if e.Tier == tier && (namespace == "" || e.Namespace == namespace) {
			result = append(result, *e)
		}
	}
	return result, nil
}

func (s *InMemoryStore) ByKey(namespace, key string) (*MemoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.Namespace == namespace && e.Key == key {
			cp := *e
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("memory entry not found: %s/%s", namespace, key)
}
