package truth_test

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/truth"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestUnknownRegistry_RegisterAndGet(t *testing.T) {
	reg := truth.NewInMemoryUnknownRegistry()

	u := &contracts.Unknown{
		ID:          "u1",
		Description: "Rate limit unknown",
		Impact:      contracts.UnknownImpactDegrading,
	}
	if err := reg.Register(u); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	got, err := reg.Get("u1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil")
	}
	if got.Description != "Rate limit unknown" {
		t.Fatalf("description mismatch: %s", got.Description)
	}
	if got.Resolved {
		t.Fatal("expected unresolved")
	}
}

func TestUnknownRegistry_DuplicateRegister(t *testing.T) {
	reg := truth.NewInMemoryUnknownRegistry()

	u := &contracts.Unknown{ID: "u1", Description: "test", Impact: contracts.UnknownImpactBlocking}
	if err := reg.Register(u); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(u); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestUnknownRegistry_Resolve(t *testing.T) {
	now := time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)
	reg := truth.NewInMemoryUnknownRegistry().WithClock(fixedClock(now))

	u := &contracts.Unknown{ID: "u1", Description: "test", Impact: contracts.UnknownImpactBlocking}
	if err := reg.Register(u); err != nil {
		t.Fatal(err)
	}

	if err := reg.Resolve("u1", "Confirmed rate limit is 100/min"); err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	got, _ := reg.Get("u1")
	if !got.Resolved {
		t.Fatal("expected resolved")
	}
	if got.Resolution != "Confirmed rate limit is 100/min" {
		t.Fatalf("resolution mismatch: %s", got.Resolution)
	}
	if got.ResolvedAt != now {
		t.Fatalf("resolved_at mismatch: %v", got.ResolvedAt)
	}
}

func TestUnknownRegistry_ResolveAlreadyResolved(t *testing.T) {
	reg := truth.NewInMemoryUnknownRegistry()

	u := &contracts.Unknown{ID: "u1", Description: "test", Impact: contracts.UnknownImpactBlocking}
	_ = reg.Register(u)
	_ = reg.Resolve("u1", "fixed")

	if err := reg.Resolve("u1", "again"); err == nil {
		t.Fatal("expected error resolving already-resolved")
	}
}

func TestUnknownRegistry_ResolveNotFound(t *testing.T) {
	reg := truth.NewInMemoryUnknownRegistry()
	if err := reg.Resolve("nonexistent", "fix"); err == nil {
		t.Fatal("expected not found error")
	}
}

func TestUnknownRegistry_GetNotFound(t *testing.T) {
	reg := truth.NewInMemoryUnknownRegistry()
	got, err := reg.Get("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("expected nil for not found")
	}
}

func TestUnknownRegistry_ListBlocking(t *testing.T) {
	reg := truth.NewInMemoryUnknownRegistry()

	_ = reg.Register(&contracts.Unknown{
		ID:              "u1",
		Impact:          contracts.UnknownImpactBlocking,
		BlockingStepIDs: []string{"step-1", "step-2"},
	})
	_ = reg.Register(&contracts.Unknown{
		ID:              "u2",
		Impact:          contracts.UnknownImpactBlocking,
		BlockingStepIDs: []string{"step-2"},
	})
	_ = reg.Register(&contracts.Unknown{
		ID:     "u3",
		Impact: contracts.UnknownImpactInformational,
	})

	blocking, err := reg.ListBlocking("step-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(blocking) != 2 {
		t.Fatalf("expected 2 blocking, got %d", len(blocking))
	}

	blocking1, _ := reg.ListBlocking("step-1")
	if len(blocking1) != 1 {
		t.Fatalf("expected 1 blocking for step-1, got %d", len(blocking1))
	}
}

func TestUnknownRegistry_ListBlocking_ExcludesResolved(t *testing.T) {
	reg := truth.NewInMemoryUnknownRegistry()

	_ = reg.Register(&contracts.Unknown{
		ID:              "u1",
		Impact:          contracts.UnknownImpactBlocking,
		BlockingStepIDs: []string{"step-1"},
	})
	_ = reg.Resolve("u1", "fixed")

	blocking, _ := reg.ListBlocking("step-1")
	if len(blocking) != 0 {
		t.Fatalf("expected 0 blocking after resolve, got %d", len(blocking))
	}
}

func TestUnknownRegistry_ListUnresolved(t *testing.T) {
	reg := truth.NewInMemoryUnknownRegistry()

	_ = reg.Register(&contracts.Unknown{ID: "u1", Impact: contracts.UnknownImpactBlocking})
	_ = reg.Register(&contracts.Unknown{ID: "u2", Impact: contracts.UnknownImpactDegrading})
	_ = reg.Resolve("u1", "done")

	unresolved, _ := reg.ListUnresolved()
	if len(unresolved) != 1 || unresolved[0].ID != "u2" {
		t.Fatalf("expected [u2], got %v", unresolved)
	}
}

func TestUnknownRegistry_ListAll(t *testing.T) {
	reg := truth.NewInMemoryUnknownRegistry()

	_ = reg.Register(&contracts.Unknown{ID: "u1", Impact: contracts.UnknownImpactBlocking})
	_ = reg.Register(&contracts.Unknown{ID: "u2", Impact: contracts.UnknownImpactDegrading})
	_ = reg.Resolve("u1", "done")

	all, _ := reg.ListAll()
	if len(all) != 2 {
		t.Fatalf("expected 2, got %d", len(all))
	}
}
