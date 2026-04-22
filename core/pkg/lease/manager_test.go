package lease_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/lease"
)

var (
	ctx       = context.Background()
	baseTime  = time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)
	clockTime = baseTime
)

func clock() time.Time { return clockTime }

func resetClock() { clockTime = baseTime }

func advanceClock(d time.Duration) { clockTime = clockTime.Add(d) }

func newManager() *lease.InMemoryLeaseManager {
	resetClock()
	return lease.NewInMemoryLeaseManager().WithClock(clock)
}

func validRequest() lease.LeaseRequest {
	return lease.LeaseRequest{
		RunID:           "run-1",
		WorkspacePath:   "/workspace",
		Backend:         "docker",
		ProfileName:     "net-limited",
		TTL:             1 * time.Hour,
		EffectGraphHash: "sha256:abc",
	}
}

func TestAcquire(t *testing.T) {
	m := newManager()
	l, err := m.Acquire(ctx, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if l.LeaseID == "" {
		t.Fatal("expected lease ID")
	}
	if l.Status != lease.LeaseStatusPending {
		t.Fatalf("expected PENDING, got %s", l.Status)
	}
	if l.ExpiresAt != baseTime.Add(1*time.Hour) {
		t.Fatalf("expected expiry at base+1h, got %v", l.ExpiresAt)
	}
}

func TestAcquire_MissingFields(t *testing.T) {
	m := newManager()
	_, err := m.Acquire(ctx, lease.LeaseRequest{})
	if err == nil {
		t.Fatal("expected error for missing fields")
	}
}

func TestActivate(t *testing.T) {
	m := newManager()
	l, _ := m.Acquire(ctx, validRequest())

	if err := m.Activate(ctx, l.LeaseID, "sbx-123"); err != nil {
		t.Fatal(err)
	}

	got, _ := m.Get(ctx, l.LeaseID)
	if got.Status != lease.LeaseStatusActive {
		t.Fatalf("expected ACTIVE, got %s", got.Status)
	}
	if got.SandboxID != "sbx-123" {
		t.Fatalf("expected sandbox ID sbx-123, got %s", got.SandboxID)
	}
}

func TestActivate_NotPending(t *testing.T) {
	m := newManager()
	l, _ := m.Acquire(ctx, validRequest())
	_ = m.Activate(ctx, l.LeaseID, "sbx-1")

	// Try to activate again.
	if err := m.Activate(ctx, l.LeaseID, "sbx-2"); err == nil {
		t.Fatal("expected error activating non-PENDING lease")
	}
}

func TestComplete(t *testing.T) {
	m := newManager()
	l, _ := m.Acquire(ctx, validRequest())
	_ = m.Activate(ctx, l.LeaseID, "sbx-1")

	if err := m.Complete(ctx, l.LeaseID); err != nil {
		t.Fatal(err)
	}

	got, _ := m.Get(ctx, l.LeaseID)
	if got.Status != lease.LeaseStatusCompleted {
		t.Fatalf("expected COMPLETED, got %s", got.Status)
	}
	if !got.IsTerminal() {
		t.Fatal("completed lease should be terminal")
	}
}

func TestComplete_NotActive(t *testing.T) {
	m := newManager()
	l, _ := m.Acquire(ctx, validRequest())

	if err := m.Complete(ctx, l.LeaseID); err == nil {
		t.Fatal("expected error completing PENDING lease")
	}
}

func TestExtend(t *testing.T) {
	m := newManager()
	l, _ := m.Acquire(ctx, validRequest())
	_ = m.Activate(ctx, l.LeaseID, "sbx-1")

	if err := m.Extend(ctx, l.LeaseID, 30*time.Minute); err != nil {
		t.Fatal(err)
	}

	got, _ := m.Get(ctx, l.LeaseID)
	expectedExpiry := baseTime.Add(1*time.Hour + 30*time.Minute)
	if got.ExpiresAt != expectedExpiry {
		t.Fatalf("expected expiry at %v, got %v", expectedExpiry, got.ExpiresAt)
	}
}

func TestRevoke(t *testing.T) {
	m := newManager()
	l, _ := m.Acquire(ctx, validRequest())
	_ = m.Activate(ctx, l.LeaseID, "sbx-1")

	if err := m.Revoke(ctx, l.LeaseID, "security concern"); err != nil {
		t.Fatal(err)
	}

	got, _ := m.Get(ctx, l.LeaseID)
	if got.Status != lease.LeaseStatusRevoked {
		t.Fatalf("expected REVOKED, got %s", got.Status)
	}
	if got.RevokeReason != "security concern" {
		t.Fatalf("expected reason, got %s", got.RevokeReason)
	}
}

func TestRevoke_Terminal(t *testing.T) {
	m := newManager()
	l, _ := m.Acquire(ctx, validRequest())
	_ = m.Activate(ctx, l.LeaseID, "sbx-1")
	_ = m.Complete(ctx, l.LeaseID)

	if err := m.Revoke(ctx, l.LeaseID, "too late"); err == nil {
		t.Fatal("expected error revoking completed lease")
	}
}

func TestGetNotFound(t *testing.T) {
	m := newManager()
	got, err := m.Get(ctx, "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("expected nil for not found")
	}
}

func TestListActive(t *testing.T) {
	m := newManager()
	l1, _ := m.Acquire(ctx, validRequest())
	l2, _ := m.Acquire(ctx, validRequest())
	_ = m.Activate(ctx, l1.LeaseID, "sbx-1")
	_ = m.Activate(ctx, l2.LeaseID, "sbx-2")
	_ = m.Complete(ctx, l1.LeaseID)

	active, _ := m.ListActive(ctx)
	// l1 completed, l2 active → only l2 plus any pending.
	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}
}

func TestExpireStale(t *testing.T) {
	m := newManager()
	l, _ := m.Acquire(ctx, validRequest())
	_ = m.Activate(ctx, l.LeaseID, "sbx-1")

	// Advance past TTL.
	advanceClock(2 * time.Hour)

	expired, _ := m.ExpireStale(ctx)
	if expired != 1 {
		t.Fatalf("expected 1 expired, got %d", expired)
	}

	got, _ := m.Get(ctx, l.LeaseID)
	if got.Status != lease.LeaseStatusExpired {
		t.Fatalf("expected EXPIRED, got %s", got.Status)
	}
}

func TestExpireStale_NotYetExpired(t *testing.T) {
	m := newManager()
	l, _ := m.Acquire(ctx, validRequest())
	_ = m.Activate(ctx, l.LeaseID, "sbx-1")

	// Only advance 30 min (TTL is 1h).
	advanceClock(30 * time.Minute)

	expired, _ := m.ExpireStale(ctx)
	if expired != 0 {
		t.Fatalf("expected 0 expired, got %d", expired)
	}
}
