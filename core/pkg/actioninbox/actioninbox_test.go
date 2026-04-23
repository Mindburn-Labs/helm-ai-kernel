package actioninbox_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/actioninbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestItem(id, managerID string) *actioninbox.InboxItem {
	return &actioninbox.InboxItem{
		ItemID:     id,
		ProposalID: "prop-" + id,
		EmployeeID: "emp-1",
		ManagerID:  managerID,
		Title:      "Test action " + id,
		Summary:    "Needs approval",
		RiskClass:  "R2",
		Status:     actioninbox.StatusPending,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(1 * time.Hour),
	}
}

func TestEnqueueAndGet(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	item := newTestItem("item-1", "mgr-1")
	err := store.Enqueue(ctx, item)
	require.NoError(t, err)

	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, "item-1", got.ItemID)
	assert.Equal(t, actioninbox.StatusPending, got.Status)
	assert.Equal(t, "mgr-1", got.ManagerID)
}

func TestEnqueue_DuplicateReturnsError(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	item := newTestItem("item-1", "mgr-1")
	require.NoError(t, store.Enqueue(ctx, item))

	err := store.Enqueue(ctx, item)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestListPending_FiltersByManagerID(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	require.NoError(t, store.Enqueue(ctx, newTestItem("a1", "mgr-alice")))
	require.NoError(t, store.Enqueue(ctx, newTestItem("a2", "mgr-alice")))
	require.NoError(t, store.Enqueue(ctx, newTestItem("b1", "mgr-bob")))

	aliceItems, err := store.ListPending(ctx, "mgr-alice", 10)
	require.NoError(t, err)
	assert.Len(t, aliceItems, 2)

	bobItems, err := store.ListPending(ctx, "mgr-bob", 10)
	require.NoError(t, err)
	assert.Len(t, bobItems, 1)

	noItems, err := store.ListPending(ctx, "mgr-nobody", 10)
	require.NoError(t, err)
	assert.Len(t, noItems, 0)
}

func TestApprove_ChangesStatus(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	require.NoError(t, store.Enqueue(ctx, newTestItem("item-1", "mgr-1")))

	err := store.Approve(ctx, "item-1", "approver-1")
	require.NoError(t, err)

	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusApproved, got.Status)
}

func TestApprove_NonPendingFails(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	require.NoError(t, store.Enqueue(ctx, newTestItem("item-1", "mgr-1")))
	require.NoError(t, store.Approve(ctx, "item-1", "approver-1"))

	// Approving again should fail (already approved).
	err := store.Approve(ctx, "item-1", "approver-2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not pending")
}

func TestDeny_ChangesStatus(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	require.NoError(t, store.Enqueue(ctx, newTestItem("item-1", "mgr-1")))

	err := store.Deny(ctx, "item-1", "too risky", "principal-1")
	require.NoError(t, err)

	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusDenied, got.Status)
}

func TestDefer_ChangesStatus(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	require.NoError(t, store.Enqueue(ctx, newTestItem("item-1", "mgr-1")))

	later := time.Now().UTC().Add(24 * time.Hour)
	err := store.Defer(ctx, "item-1", later)
	require.NoError(t, err)

	got, err := store.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusDeferred, got.Status)
}

func TestRouteForRiskClass(t *testing.T) {
	router := actioninbox.NewApprovalRouter()

	tests := []struct {
		riskClass     string
		wantRouteType string
	}{
		{"R0", "auto"},
		{"R1", "auto"},
		{"R2", "single_human"},
		{"R3", "dual_control"},
		{"R4", "dual_control"},
	}

	for _, tt := range tests {
		t.Run(tt.riskClass, func(t *testing.T) {
			route := router.RouteForRiskClass(tt.riskClass)
			assert.Equal(t, tt.wantRouteType, route.RouteType)
		})
	}
}

func TestExpiredItem(t *testing.T) {
	store := actioninbox.NewInMemoryInboxStore()
	ctx := context.Background()

	item := &actioninbox.InboxItem{
		ItemID:    "expired-1",
		ManagerID: "mgr-1",
		Title:     "Expired action",
		RiskClass: "R2",
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour), // Already expired
	}
	require.NoError(t, store.Enqueue(ctx, item))

	got, err := store.Get(ctx, "expired-1")
	require.NoError(t, err)
	assert.Equal(t, actioninbox.StatusExpired, got.Status)

	// Expired items should not appear in pending list.
	pending, err := store.ListPending(ctx, "mgr-1", 10)
	require.NoError(t, err)
	assert.Len(t, pending, 0)
}
