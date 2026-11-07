package kernel

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── CSNF Tests ───────────────────────────────────────────────────

// e-acute as combining sequence (e + combining acute)

// CSNF converts integer-valued floats to int (42.0 -> 42)

// Hangul syllable composed from jamo
// ㄱ + ㅏ → 가

// ── Scheduler Tests ──────────────────────────────────────────────

// Drain and verify monotonicity of scheduling order

// ── FreezeController Tests ───────────────────────────────────────

func TestDeepFreezeControllerInitiallyUnfrozen(t *testing.T) {
	fc := NewFreezeController()
	if fc.IsFrozen() {
		t.Fatal("should start unfrozen")
	}
}

func TestDeepFreezeControllerFreezeUnfreeze(t *testing.T) {
	fc := NewFreezeController()
	_, err := fc.Freeze("admin")
	if err != nil || !fc.IsFrozen() {
		t.Fatal("freeze should succeed")
	}
	_, err = fc.Unfreeze("admin")
	if err != nil || fc.IsFrozen() {
		t.Fatal("unfreeze should succeed")
	}
}

func TestDeepFreezeControllerDoubleFreeze(t *testing.T) {
	fc := NewFreezeController()
	fc.Freeze("admin")
	_, err := fc.Freeze("admin")
	if err == nil {
		t.Fatal("double freeze should error")
	}
}

func TestDeepFreezeControllerDoubleUnfreeze(t *testing.T) {
	fc := NewFreezeController()
	_, err := fc.Unfreeze("admin")
	if err == nil {
		t.Fatal("unfreeze without freeze should error")
	}
}

func TestDeepFreezeControllerReceipts(t *testing.T) {
	fc := NewFreezeController()
	fc.Freeze("a")
	fc.Unfreeze("b")
	receipts := fc.Receipts()
	if len(receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(receipts))
	}
	if receipts[0].Action != "freeze" || receipts[1].Action != "unfreeze" {
		t.Fatal("receipt actions mismatch")
	}
}

func TestDeepFreezeControllerConcurrent(t *testing.T) {
	fc := NewFreezeController()
	var wg sync.WaitGroup
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = fc.IsFrozen()
			if idx%2 == 0 {
				fc.Freeze(fmt.Sprintf("p-%d", idx))
			} else {
				fc.Unfreeze(fmt.Sprintf("p-%d", idx))
			}
		}(i)
	}
	wg.Wait()
}

func TestDeepFreezeReceiptHashDeterministic(t *testing.T) {
	clk := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fc := NewFreezeController().WithClock(func() time.Time { return clk })
	r1, _ := fc.Freeze("admin")
	fc2 := NewFreezeController().WithClock(func() time.Time { return clk })
	r2, _ := fc2.Freeze("admin")
	if r1.ContentHash != r2.ContentHash {
		t.Fatal("same inputs/clock should produce same hash")
	}
}
