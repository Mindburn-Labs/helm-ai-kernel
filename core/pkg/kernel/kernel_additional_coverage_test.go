package kernel

import (
	"sync"
	"testing"
)

// ─── 1: DependencyGraph hash determinism with unicode node IDs ─

// ─── 2: DependencyGraph hash changes with different content ───

// ─── 3: DependencyGraph Finalize identifies roots and leaves ──

// ─── 4: RetrySchedule — equal timestamps produce same delay ──

// ─── 5: RetrySchedule — exponential caps at max ──────────────

// 100 * 2^10 = 102400, capped at 500

// ─── 6: RetrySchedule — linear delay ─────────────────────────

// ─── 7: RetrySchedule — unknown strategy defaults to base ────

// ─── 8: NondeterminismTracker — all sources captured ──────────

// ─── 9: NondeterminismTracker — Receipt for unknown run ───────

// ─── 10: NondeterminismTracker — Receipt content hash ─────────

// ─── 11: FreezeController — concurrent freeze/unfreeze ────────

func TestExt_FreezeControllerConcurrent(t *testing.T) {
	fc := NewFreezeController()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = fc.IsFrozen()
		}()
	}
	wg.Wait()
}

func TestExt_FreezeControllerConcurrentToggle(t *testing.T) {
	fc := NewFreezeController()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fc.Freeze("admin")
			fc.Unfreeze("admin")
		}()
	}
	wg.Wait()
	// No panic = success
}

func TestExt_FreezeStateDetails(t *testing.T) {
	fc := NewFreezeController()
	fc.Freeze("admin-1")
	isFrozen, principal, ts := fc.FreezeState()
	if !isFrozen || principal != "admin-1" || ts.IsZero() {
		t.Fatalf("unexpected state: frozen=%v principal=%s ts=%v", isFrozen, principal, ts)
	}
}

func TestExt_ContextGuardEmptyBootPasses(t *testing.T) {
	cg := NewContextGuardWithFingerprint("")
	if err := cg.Validate("anything"); err != nil {
		t.Fatalf("empty boot fingerprint should pass, got %v", err)
	}
}

func TestExt_ContextGuardMatchingPasses(t *testing.T) {
	cg := NewContextGuardWithFingerprint("fp-123")
	if err := cg.Validate("fp-123"); err != nil {
		t.Fatalf("matching fingerprint should pass, got %v", err)
	}
}

func TestExt_ContextGuardMismatchErrorType(t *testing.T) {
	cg := NewContextGuardWithFingerprint("fp-boot")
	err := cg.Validate("fp-different")
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*ContextMismatchError); !ok {
		t.Fatal("expected ContextMismatchError type")
	}
}

func TestExt_ContextGuardStats(t *testing.T) {
	cg := NewContextGuardWithFingerprint("fp")
	cg.Validate("fp")
	cg.Validate("other")
	cg.Validate("fp")
	validations, mismatches := cg.Stats()
	if validations != 3 || mismatches != 1 {
		t.Fatalf("expected 3 validations/1 mismatch, got %d/%d", validations, mismatches)
	}
}

func TestExt_ContextGuardBootFingerprint(t *testing.T) {
	cg := NewContextGuard()
	fp := cg.BootFingerprint()
	if fp == "" {
		t.Fatal("boot fingerprint should be non-empty")
	}
}
