package actioninbox

import (
	"context"
	"time"
)

// Inbox is the governance inbox interface. Implementations must be
// fail-closed: if an approval cannot be verified, the action is denied.
type Inbox interface {
	// Enqueue adds an item to the inbox for approval.
	Enqueue(ctx context.Context, item *InboxItem) error

	// Get retrieves an inbox item by ID.
	Get(ctx context.Context, itemID string) (*InboxItem, error)

	// ListPending returns pending items for a given manager, up to limit.
	ListPending(ctx context.Context, managerID string, limit int) ([]*InboxItem, error)

	// Approve marks an item as approved by the given approver.
	Approve(ctx context.Context, itemID string, approverID string) error

	// Deny marks an item as denied with a reason.
	Deny(ctx context.Context, itemID string, reason string, principalID string) error

	// Defer postpones review of an item until the given time.
	Defer(ctx context.Context, itemID string, until time.Time) error
}
