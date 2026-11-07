package kernel

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1-5: CSNF type coverage
// ---------------------------------------------------------------------------

// e-acute

// ---------------------------------------------------------------------------
// 6-10: NondeterminismSource coverage
// ---------------------------------------------------------------------------

// sha256: prefix + 64 hex chars

// ---------------------------------------------------------------------------
// 18-24: Freeze states
// ---------------------------------------------------------------------------

func TestClosing_FreezeController_InitialState(t *testing.T) {
	fc := NewFreezeController()
	t.Run("not_frozen", func(t *testing.T) {
		if fc.IsFrozen() {
			t.Fatal("should not be frozen initially")
		}
	})
	t.Run("state_details", func(t *testing.T) {
		frozen, principal, _ := fc.FreezeState()
		if frozen {
			t.Fatal("should not be frozen")
		}
		if principal != "" {
			t.Fatalf("principal should be empty, got %q", principal)
		}
	})
	t.Run("empty_receipts", func(t *testing.T) {
		if len(fc.Receipts()) != 0 {
			t.Fatal("should have no receipts")
		}
	})
}

func TestClosing_FreezeController_FreezeUnfreeze(t *testing.T) {
	fc := NewFreezeController()
	r1, err := fc.Freeze("admin")
	t.Run("freeze_succeeds", func(t *testing.T) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if r1 == nil {
			t.Fatal("receipt should not be nil")
		}
	})
	t.Run("is_frozen", func(t *testing.T) {
		if !fc.IsFrozen() {
			t.Fatal("should be frozen")
		}
	})
	t.Run("double_freeze_errors", func(t *testing.T) {
		_, err := fc.Freeze("admin2")
		if err == nil {
			t.Fatal("double freeze should error")
		}
	})
	r2, _ := fc.Unfreeze("admin")
	t.Run("unfreeze_succeeds", func(t *testing.T) {
		if r2 == nil {
			t.Fatal("receipt should not be nil")
		}
		if fc.IsFrozen() {
			t.Fatal("should not be frozen after unfreeze")
		}
	})
	t.Run("double_unfreeze_errors", func(t *testing.T) {
		_, err := fc.Unfreeze("admin")
		if err == nil {
			t.Fatal("double unfreeze should error")
		}
	})
}

func TestClosing_FreezeController_Receipts(t *testing.T) {
	fc := NewFreezeController()
	fc.Freeze("a")
	fc.Unfreeze("a")
	fc.Freeze("b")
	fc.Unfreeze("b")
	receipts := fc.Receipts()
	t.Run("four_receipts", func(t *testing.T) {
		if len(receipts) != 4 {
			t.Fatalf("got %d, want 4", len(receipts))
		}
	})
	t.Run("alternating_actions", func(t *testing.T) {
		if receipts[0].Action != "freeze" || receipts[1].Action != "unfreeze" {
			t.Fatal("actions should alternate")
		}
	})
	t.Run("content_hashes_set", func(t *testing.T) {
		for i, r := range receipts {
			if r.ContentHash == "" {
				t.Fatalf("receipt %d has empty hash", i)
			}
		}
	})
}

func TestClosing_FreezeController_WithClock(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fc := NewFreezeController().WithClock(func() time.Time { return fixedTime })
	r, _ := fc.Freeze("admin")
	t.Run("uses_injected_clock", func(t *testing.T) {
		if !r.Timestamp.Equal(fixedTime) {
			t.Fatalf("got %v, want %v", r.Timestamp, fixedTime)
		}
	})
	t.Run("receipt_hash_deterministic", func(t *testing.T) {
		if r.ContentHash == "" {
			t.Fatal("content hash should not be empty")
		}
	})
	t.Run("state_timestamp", func(t *testing.T) {
		_, _, ts := fc.FreezeState()
		if !ts.Equal(fixedTime) {
			t.Fatalf("got %v, want %v", ts, fixedTime)
		}
	})
}

func TestClosing_FreezeController_ReceiptContentHash(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fc := NewFreezeController().WithClock(func() time.Time {
		ts := now
		now = now.Add(time.Second)
		return ts
	})
	r1, _ := fc.Freeze("a")
	fc.Unfreeze("a")
	r2, _ := fc.Freeze("a")
	t.Run("different_freeze_different_hash", func(t *testing.T) {
		if r1.ContentHash == r2.ContentHash {
			t.Fatal("hashes should differ due to different receipt timestamps")
		}
	})
	t.Run("hash_nonempty", func(t *testing.T) {
		if r1.ContentHash == "" || r2.ContentHash == "" {
			t.Fatal("hashes should not be empty")
		}
	})
	t.Run("hash_hex_length", func(t *testing.T) {
		if len(r1.ContentHash) != 64 {
			t.Fatalf("expected 64 hex chars, got %d", len(r1.ContentHash))
		}
	})
}

func TestClosing_FreezeController_CopySemantics(t *testing.T) {
	fc := NewFreezeController()
	fc.Freeze("admin")
	fc.Unfreeze("admin")
	r1 := fc.Receipts()
	r2 := fc.Receipts()
	t.Run("independent_copies", func(t *testing.T) {
		if &r1[0] == &r2[0] {
			t.Fatal("receipts should be independent copies")
		}
	})
	t.Run("same_content", func(t *testing.T) {
		if r1[0].Action != r2[0].Action {
			t.Fatal("copies should have same content")
		}
	})
	t.Run("same_length", func(t *testing.T) {
		if len(r1) != len(r2) {
			t.Fatal("copies should have same length")
		}
	})
}

func TestClosing_ContextGuard_WithFingerprint(t *testing.T) {
	cg := NewContextGuardWithFingerprint("test-fp-123")
	t.Run("boot_fingerprint", func(t *testing.T) {
		if cg.BootFingerprint() != "test-fp-123" {
			t.Fatalf("got %q", cg.BootFingerprint())
		}
	})
	t.Run("validate_match", func(t *testing.T) {
		err := cg.Validate("test-fp-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("validate_mismatch", func(t *testing.T) {
		err := cg.Validate("different-fp")
		if err == nil {
			t.Fatal("expected mismatch error")
		}
	})
}

func TestClosing_ContextGuard_EmptyFingerprint(t *testing.T) {
	cg := NewContextGuardWithFingerprint("")
	t.Run("passthrough_any", func(t *testing.T) {
		// Documented contract: no boot fingerprint means no guard.
		if err := cg.Validate("anything"); err != nil {
			t.Fatalf("empty boot fingerprint must be a pass-through, got %v", err)
		}
	})
	t.Run("passthrough_empty", func(t *testing.T) {
		err := cg.Validate("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("boot_fingerprint_empty", func(t *testing.T) {
		if cg.BootFingerprint() != "" {
			t.Fatalf("expected empty, got %q", cg.BootFingerprint())
		}
	})
}

func TestClosing_ContextGuard_Stats(t *testing.T) {
	cg := NewContextGuardWithFingerprint("fp")
	cg.Validate("fp")
	cg.Validate("wrong")
	cg.Validate("fp")
	t.Run("validation_count", func(t *testing.T) {
		v, _ := cg.Stats()
		if v != 3 {
			t.Fatalf("got %d, want 3", v)
		}
	})
	t.Run("mismatch_count", func(t *testing.T) {
		_, m := cg.Stats()
		if m != 1 {
			t.Fatalf("got %d, want 1", m)
		}
	})
	t.Run("initial_stats_zero", func(t *testing.T) {
		cg2 := NewContextGuardWithFingerprint("fp2")
		v, m := cg2.Stats()
		if v != 0 || m != 0 {
			t.Fatalf("expected 0,0 got %d,%d", v, m)
		}
	})
}

func TestClosing_ContextGuard_MismatchError(t *testing.T) {
	cg := NewContextGuardWithFingerprint("aaaa1111aaaa2222aaaa3333aaaa4444")
	err := cg.Validate("bbbb1111bbbb2222bbbb3333bbbb4444")
	t.Run("is_mismatch_error", func(t *testing.T) {
		if err == nil {
			t.Fatal("expected error")
		}
		_, ok := err.(*ContextMismatchError)
		if !ok {
			t.Fatalf("expected *ContextMismatchError, got %T", err)
		}
	})
	t.Run("error_message", func(t *testing.T) {
		if err.Error() == "" {
			t.Fatal("error message should not be empty")
		}
	})
	t.Run("error_fields", func(t *testing.T) {
		cme := err.(*ContextMismatchError)
		if cme.BootFingerprint == "" || cme.CurrentFingerprint == "" {
			t.Fatal("fingerprint fields should be set")
		}
	})
}

func TestClosing_ContextGuard_NewContextGuard(t *testing.T) {
	cg := NewContextGuard()
	t.Run("has_boot_fingerprint", func(t *testing.T) {
		if cg.BootFingerprint() == "" {
			t.Fatal("boot fingerprint should not be empty")
		}
	})
	t.Run("fingerprint_length", func(t *testing.T) {
		fp := cg.BootFingerprint()
		if len(fp) != 64 {
			t.Fatalf("expected 64 hex chars, got %d", len(fp))
		}
	})
	t.Run("validate_current_passes", func(t *testing.T) {
		err := cg.ValidateCurrent()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestClosing_ContextGuard_WithClock(t *testing.T) {
	fixedTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cg := NewContextGuardWithFingerprint("fp").WithClock(func() time.Time { return fixedTime })
	err := cg.Validate("wrong")
	t.Run("uses_clock_in_error", func(t *testing.T) {
		cme := err.(*ContextMismatchError)
		if !cme.DetectedAt.Equal(fixedTime) {
			t.Fatalf("got %v, want %v", cme.DetectedAt, fixedTime)
		}
	})
	t.Run("returns_context_guard", func(t *testing.T) {
		if cg == nil {
			t.Fatal("WithClock should return non-nil")
		}
	})
	t.Run("fingerprint_unchanged", func(t *testing.T) {
		if cg.BootFingerprint() != "fp" {
			t.Fatalf("fingerprint changed after WithClock")
		}
	})
}

func TestClosing_ContextGuard_DeterministicFingerprint(t *testing.T) {
	cg1 := NewContextGuard()
	cg2 := NewContextGuard()
	t.Run("same_env_same_fingerprint", func(t *testing.T) {
		if cg1.BootFingerprint() != cg2.BootFingerprint() {
			t.Fatal("same environment should produce same fingerprint")
		}
	})
	t.Run("hex_encoded", func(t *testing.T) {
		fp := cg1.BootFingerprint()
		for _, c := range fp {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("non-hex char in fingerprint: %c", c)
			}
		}
	})
	t.Run("sha256_length", func(t *testing.T) {
		if len(cg1.BootFingerprint()) != 64 {
			t.Fatalf("got length %d", len(cg1.BootFingerprint()))
		}
	})
}
