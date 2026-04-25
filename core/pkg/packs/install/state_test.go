package install

import (
	"errors"
	"testing"
	"time"
)

// TestMemoryStore_CRUD exercises basic Get/Put/Delete/List roundtrips.
func TestMemoryStore_CRUD(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)

	if _, err := store.Get("nope"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("Get missing: want ErrStateNotFound, got %v", err)
	}

	a := &State{PackID: "pack-a", Version: "0.1.0", Status: "installed", UpdatedAt: now}
	b := &State{PackID: "pack-b", Version: "0.2.0", Status: "installed", UpdatedAt: now}

	if err := store.Put(a); err != nil {
		t.Fatalf("Put a: %v", err)
	}
	if err := store.Put(b); err != nil {
		t.Fatalf("Put b: %v", err)
	}

	got, err := store.Get("pack-a")
	if err != nil {
		t.Fatalf("Get a: %v", err)
	}
	if got.Version != "0.1.0" || got.Status != "installed" {
		t.Fatalf("Get a returned wrong state: %+v", got)
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List length: want 2, got %d", len(list))
	}
	// Deterministic ordering by PackID.
	if list[0].PackID != "pack-a" || list[1].PackID != "pack-b" {
		t.Fatalf("List not sorted by PackID: %q, %q", list[0].PackID, list[1].PackID)
	}

	if err := store.Delete("pack-a"); err != nil {
		t.Fatalf("Delete a: %v", err)
	}
	if _, err := store.Get("pack-a"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("Get after Delete: want ErrStateNotFound, got %v", err)
	}
	if err := store.Delete("pack-a"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("Delete missing: want ErrStateNotFound, got %v", err)
	}
}

// TestMemoryStore_Clone_Isolation confirms that mutating a returned
// state does not leak into the stored copy.
func TestMemoryStore_Clone_Isolation(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	original := &State{
		PackID:      "pack-x",
		Version:     "0.1.0",
		Status:      "installed",
		InstalledAt: timePtr(now),
		VerifiedAt:  timePtr(now),
		UpdatedAt:   now,
	}
	if err := store.Put(original); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// External mutation of the caller's original must not leak.
	original.Status = "hacked"
	fetched, err := store.Get("pack-x")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if fetched.Status != "installed" {
		t.Fatalf("Put must clone: caller mutation leaked, got Status=%q", fetched.Status)
	}

	// External mutation of the fetched state must not leak either.
	fetched.Status = "hacked"
	refetched, err := store.Get("pack-x")
	if err != nil {
		t.Fatalf("Get second: %v", err)
	}
	if refetched.Status != "installed" {
		t.Fatalf("Get must clone: caller mutation leaked, got Status=%q", refetched.Status)
	}
}

// TestMemoryStore_PutValidates confirms Put rejects invalid inputs.
func TestMemoryStore_PutValidates(t *testing.T) {
	store := NewMemoryStore()

	if err := store.Put(nil); err == nil {
		t.Fatalf("Put nil: want error")
	}
	if err := store.Put(&State{}); err == nil {
		t.Fatalf("Put empty PackID: want error")
	}
}
