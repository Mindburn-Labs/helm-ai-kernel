package actioninbox

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// InMemoryInboxStore implements Inbox using an in-memory map.
// Thread-safe via RWMutex.
type InMemoryInboxStore struct {
	mu    sync.RWMutex
	items map[string]*InboxItem
}

// NewInMemoryInboxStore creates a new in-memory inbox store.
func NewInMemoryInboxStore() *InMemoryInboxStore {
	return &InMemoryInboxStore{
		items: make(map[string]*InboxItem),
	}
}

func (s *InMemoryInboxStore) Enqueue(ctx context.Context, item *InboxItem) error {
	if item == nil {
		return fmt.Errorf("actioninbox: item must not be nil")
	}
	if item.ItemID == "" {
		return fmt.Errorf("actioninbox: item_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.items[item.ItemID]; exists {
		return fmt.Errorf("actioninbox: item %q already exists", item.ItemID)
	}

	// Store a copy to prevent external mutation.
	val := *item
	val.Status = StatusPending
	s.items[item.ItemID] = &val
	return nil
}

func (s *InMemoryInboxStore) Get(ctx context.Context, itemID string) (*InboxItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item, ok := s.items[itemID]
	if !ok {
		return nil, fmt.Errorf("actioninbox: item %q not found", itemID)
	}

	// Check expiry on read.
	if item.Status == StatusPending && !item.ExpiresAt.IsZero() && time.Now().After(item.ExpiresAt) {
		// Mark expired (upgrade to write lock).
		s.mu.RUnlock()
		s.mu.Lock()
		item.Status = StatusExpired
		s.mu.Unlock()
		s.mu.RLock()
	}

	val := *item
	return &val, nil
}

func (s *InMemoryInboxStore) ListPending(ctx context.Context, managerID string, limit int) ([]*InboxItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*InboxItem
	for _, item := range s.items {
		if item.ManagerID == managerID && item.Status == StatusPending {
			// Check expiry.
			if !item.ExpiresAt.IsZero() && time.Now().After(item.ExpiresAt) {
				continue
			}
			val := *item
			result = append(result, &val)
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func (s *InMemoryInboxStore) Approve(ctx context.Context, itemID string, approverID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[itemID]
	if !ok {
		return fmt.Errorf("actioninbox: item %q not found", itemID)
	}
	if item.Status != StatusPending {
		return fmt.Errorf("actioninbox: item %q is not pending (status=%s)", itemID, item.Status)
	}

	item.Status = StatusApproved
	return nil
}

func (s *InMemoryInboxStore) Deny(ctx context.Context, itemID string, reason string, principalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[itemID]
	if !ok {
		return fmt.Errorf("actioninbox: item %q not found", itemID)
	}
	if item.Status != StatusPending {
		return fmt.Errorf("actioninbox: item %q is not pending (status=%s)", itemID, item.Status)
	}

	item.Status = StatusDenied
	return nil
}

func (s *InMemoryInboxStore) Defer(ctx context.Context, itemID string, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[itemID]
	if !ok {
		return fmt.Errorf("actioninbox: item %q not found", itemID)
	}
	if item.Status != StatusPending {
		return fmt.Errorf("actioninbox: item %q is not pending (status=%s)", itemID, item.Status)
	}

	item.Status = StatusDeferred
	item.ExpiresAt = until
	return nil
}
