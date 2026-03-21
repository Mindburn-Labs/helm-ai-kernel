package context

import (
	"fmt"
	"sync"
)

// BundleStore is a concrete store for context and documentation bundles.
type BundleStore struct {
	mu       sync.RWMutex
	contexts map[string]*ContextBundle    // bundleID → bundle
	docs     map[string]*DocumentBundle   // bundleID → bundle
}

// NewBundleStore creates a new in-memory bundle store.
func NewBundleStore() *BundleStore {
	return &BundleStore{
		contexts: make(map[string]*ContextBundle),
		docs:     make(map[string]*DocumentBundle),
	}
}

// PutContext stores a context bundle.
func (s *BundleStore) PutContext(b *ContextBundle) error {
	if err := ValidateBundle(*b); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contexts[b.BundleID] = b
	return nil
}

// GetContext retrieves a context bundle by ID.
func (s *BundleStore) GetContext(bundleID string) (*ContextBundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.contexts[bundleID]
	if !ok {
		return nil, fmt.Errorf("context bundle %s not found", bundleID)
	}
	return b, nil
}

// ListContexts lists all context bundles.
func (s *BundleStore) ListContexts() []*ContextBundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*ContextBundle
	for _, b := range s.contexts {
		result = append(result, b)
	}
	return result
}

// PutDocument stores a documentation bundle.
func (s *BundleStore) PutDocument(b *DocumentBundle) error {
	if b.BundleID == "" {
		return fmt.Errorf("document bundle requires bundle_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[b.BundleID] = b
	return nil
}

// GetDocument retrieves a documentation bundle by ID.
func (s *BundleStore) GetDocument(bundleID string) (*DocumentBundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.docs[bundleID]
	if !ok {
		return nil, fmt.Errorf("document bundle %s not found", bundleID)
	}
	return b, nil
}

// ListDocuments lists all documentation bundles.
func (s *BundleStore) ListDocuments() []*DocumentBundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*DocumentBundle
	for _, b := range s.docs {
		result = append(result, b)
	}
	return result
}
