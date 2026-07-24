package actioninbox

import (
	"context"
	"fmt"
	"sort"
	"strings"
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

// copyItem deep-copies an inbox item, including the structured denial
// record and the context map. Shallow copies would alias the stored Denial
// pointer (letting callers mutate denial evidence) and the Context map
// (letting callers rewrite session_id after Enqueue/Get and corrupt
// DenyCascade same-session scoping).
func copyItem(item *InboxItem) *InboxItem {
	val := *item
	if item.Denial != nil {
		d := *item.Denial
		val.Denial = &d
	}
	if item.Context != nil {
		ctx := make(map[string]any, len(item.Context))
		for k, v := range item.Context {
			ctx[k] = v
		}
		val.Context = ctx
	}
	return &val
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
	val := copyItem(item)
	val.Status = StatusPending
	s.items[item.ItemID] = val
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

	return copyItem(item), nil
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
			result = append(result, copyItem(item))
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
	return s.DenyWithFeedback(ctx, itemID, reason, ReasonHumanRejected, principalID)
}

// DenyWithFeedback marks an item as denied and attaches a structured,
// model-actionable denial record (reject-with-feedback): the human's
// steering text is preserved on the item so the requesting agent can
// retrieve it and self-correct instead of retrying blind.
func (s *InMemoryInboxStore) DenyWithFeedback(ctx context.Context, itemID string, feedback string, reasonCode string, principalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[itemID]
	if !ok {
		return fmt.Errorf("actioninbox: item %q not found", itemID)
	}
	if item.Status != StatusPending {
		return fmt.Errorf("actioninbox: item %q is not pending (status=%s)", itemID, item.Status)
	}
	if strings.TrimSpace(reasonCode) == "" {
		reasonCode = ReasonHumanRejected
	}

	item.Status = StatusDenied
	item.Denial = &DenialRecord{
		SchemaVersion: DenyFeedbackSchemaVersion,
		ReasonCode:    reasonCode,
		Explanation:   "The requested action was reviewed and rejected by the approving principal.",
		Feedback:      feedback,
		Remediation:   "Do not retry the identical request. Adjust the proposal according to the feedback, or abandon it.",
		Escalation:    "If the rejection seems mistaken, escalate to the approving principal with this item's receipt and content hash.",
		PrincipalID:   principalID,
		DecidedAt:     time.Now().UTC(),
	}
	return nil
}

// DenyCascade marks an item as denied with feedback, then cascade-rejects
// every other still-pending item that is an identical same-session ask:
// same non-empty ContentHash and same non-empty session ID. Cascaded items
// are denied, never approved — the cascade only ever narrows, preserving
// fail-closed semantics. It returns the IDs of the cascaded items
// (excluding itemID).
func (s *InMemoryInboxStore) DenyCascade(ctx context.Context, itemID string, feedback string, principalID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[itemID]
	if !ok {
		return nil, fmt.Errorf("actioninbox: item %q not found", itemID)
	}
	if item.Status != StatusPending {
		return nil, fmt.Errorf("actioninbox: item %q is not pending (status=%s)", itemID, item.Status)
	}

	now := time.Now().UTC()
	item.Status = StatusDenied
	item.Denial = &DenialRecord{
		SchemaVersion: DenyFeedbackSchemaVersion,
		ReasonCode:    ReasonHumanRejected,
		Explanation:   "The requested action was reviewed and rejected by the approving principal.",
		Feedback:      feedback,
		Remediation:   "Do not retry the identical request. Adjust the proposal according to the feedback, or abandon it.",
		Escalation:    "If the rejection seems mistaken, escalate to the approving principal with this item's receipt and content hash.",
		PrincipalID:   principalID,
		DecidedAt:     now,
	}

	var cascaded []string
	if item.ContentHash == "" {
		// Without a content hash there is no safe identity for "identical
		// ask"; fail closed by refusing to guess.
		return cascaded, nil
	}
	session := item.SessionID()
	if session == "" {
		// Without a session ID there is no safe identity for "same
		// session": two unknown-session asks could be unrelated. Fail
		// closed by refusing to cascade.
		return cascaded, nil
	}
	for _, other := range s.items {
		if other.ItemID == itemID || other.Status != StatusPending {
			continue
		}
		// Skip logically expired items: they are expired audit records
		// (lazy expiry marks them EXPIRED on read), not deniable asks —
		// a cascade must never rewrite them as DENIED.
		if !other.ExpiresAt.IsZero() && time.Now().After(other.ExpiresAt) {
			continue
		}
		// Cascade only when session IDs are equal AND non-empty: empty
		// session IDs must never compare equal here.
		if other.ContentHash != item.ContentHash || other.SessionID() != session {
			continue
		}
		other.Status = StatusDenied
		other.Denial = &DenialRecord{
			SchemaVersion: DenyFeedbackSchemaVersion,
			ReasonCode:    ReasonCascadeRejected,
			Explanation:   "An identical pending request in the same session was rejected; this duplicate was cascade-rejected.",
			Feedback:      feedback,
			CascadedFrom:  itemID,
			Remediation:   "Do not re-enqueue the identical request in this session. Adjust the proposal according to the feedback first.",
			Escalation:    "Escalate to the approving principal with the originating item's receipt if the cascade seems mistaken.",
			PrincipalID:   principalID,
			DecidedAt:     now,
		}
		cascaded = append(cascaded, other.ItemID)
	}
	sort.Strings(cascaded)
	return cascaded, nil
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
