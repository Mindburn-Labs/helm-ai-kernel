package kernel

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestFreezeController_InitiallyUnfrozen(t *testing.T) {
	fc := NewFreezeController()
	if fc.IsFrozen() {
		t.Error("FreezeController should be unfrozen initially")
	}
}

func TestFreezeController_FreezeAndUnfreeze(t *testing.T) {
	ts := time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC)
	fc := NewFreezeController().WithClock(fixedClock(ts))

	receipt, err := fc.Freeze("operator-1")
	if err != nil {
		t.Fatalf("Freeze failed: %v", err)
	}
	if !fc.IsFrozen() {
		t.Error("should be frozen after Freeze()")
	}
	if receipt.Action != "freeze" {
		t.Errorf("receipt action = %s, want freeze", receipt.Action)
	}
	if receipt.Principal != "operator-1" {
		t.Errorf("receipt principal = %s, want operator-1", receipt.Principal)
	}
	if receipt.ContentHash == "" {
		t.Error("receipt content hash must not be empty")
	}
	if receipt.Timestamp != ts {
		t.Errorf("receipt timestamp = %v, want %v", receipt.Timestamp, ts)
	}

	receipt2, err := fc.Unfreeze("operator-1")
	if err != nil {
		t.Fatalf("Unfreeze failed: %v", err)
	}
	if fc.IsFrozen() {
		t.Error("should be unfrozen after Unfreeze()")
	}
	if receipt2.Action != "unfreeze" {
		t.Errorf("receipt action = %s, want unfreeze", receipt2.Action)
	}
}

func TestFreezeController_DoubleFreezeError(t *testing.T) {
	fc := NewFreezeController()
	if _, err := fc.Freeze("op1"); err != nil {
		t.Fatalf("first freeze should succeed: %v", err)
	}
	_, err := fc.Freeze("op2")
	if err == nil {
		t.Error("second freeze should return error")
	}
	if !strings.Contains(err.Error(), "already frozen") {
		t.Errorf("error should mention 'already frozen', got: %v", err)
	}
}

func TestFreezeController_DoubleUnfreezeError(t *testing.T) {
	fc := NewFreezeController()
	_, err := fc.Unfreeze("op1")
	if err == nil {
		t.Error("unfreeze on unfrozen system should return error")
	}
	if !strings.Contains(err.Error(), "not frozen") {
		t.Errorf("error should mention 'not frozen', got: %v", err)
	}
}

func TestFreezeController_ReceiptsAccumulate(t *testing.T) {
	fc := NewFreezeController()
	fc.Freeze("op1")
	fc.Unfreeze("op2")
	fc.Freeze("op3")

	receipts := fc.Receipts()
	if len(receipts) != 3 {
		t.Fatalf("want 3 receipts, got %d", len(receipts))
	}
	if receipts[0].Action != "freeze" || receipts[0].Principal != "op1" {
		t.Errorf("receipts[0] = %+v, want freeze by op1", receipts[0])
	}
	if receipts[1].Action != "unfreeze" || receipts[1].Principal != "op2" {
		t.Errorf("receipts[1] = %+v, want unfreeze by op2", receipts[1])
	}
	if receipts[2].Action != "freeze" || receipts[2].Principal != "op3" {
		t.Errorf("receipts[2] = %+v, want freeze by op3", receipts[2])
	}
}

func TestFreezeController_ContentHashDeterministic(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	fc1 := NewFreezeController().WithClock(fixedClock(ts))
	r1, _ := fc1.Freeze("op1")

	fc2 := NewFreezeController().WithClock(fixedClock(ts))
	r2, _ := fc2.Freeze("op1")

	if r1.ContentHash != r2.ContentHash {
		t.Errorf("deterministic hashes should match: %s != %s", r1.ContentHash, r2.ContentHash)
	}
}

func TestFreezeController_FreezeState(t *testing.T) {
	ts := time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC)
	fc := NewFreezeController().WithClock(fixedClock(ts))

	frozen, by, at := fc.FreezeState()
	if frozen || by != "" || !at.IsZero() {
		t.Error("initial state should be empty")
	}

	fc.Freeze("admin")
	frozen, by, at = fc.FreezeState()
	if !frozen || by != "admin" || at != ts {
		t.Errorf("freeze state = (%v, %s, %v), want (true, admin, %v)", frozen, by, at, ts)
	}
}

func TestFreezeController_ConcurrentAccess(t *testing.T) {
	fc := NewFreezeController()
	var wg sync.WaitGroup

	// Concurrent readers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = fc.IsFrozen()
		}()
	}

	// Concurrent writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		fc.Freeze("concurrent-op")
	}()

	wg.Wait()

	// Should not panic or race — verify freeze took effect
	if !fc.IsFrozen() {
		t.Error("freeze should have taken effect")
	}
}
