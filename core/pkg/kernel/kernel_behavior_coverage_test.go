package kernel

import (
	"testing"
	"time"
)

var fixedT = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

func fixedClk() time.Time { return fixedT }

func TestCompFreezeController_InitiallyUnfrozen(t *testing.T) {
	fc := NewFreezeController()
	if fc.IsFrozen() {
		t.Fatal("new controller should not be frozen")
	}
}

func TestFreezeController_FreezeReturnReceipt(t *testing.T) {
	fc := NewFreezeController().WithClock(fixedClk)
	r, err := fc.Freeze("admin")
	if err != nil || r.Action != "freeze" || r.Principal != "admin" {
		t.Fatalf("unexpected freeze result: receipt=%+v err=%v", r, err)
	}
}

func TestFreezeController_DoubleFreezeErrors(t *testing.T) {
	fc := NewFreezeController()
	_, _ = fc.Freeze("admin")
	_, err := fc.Freeze("admin")
	if err == nil {
		t.Fatal("double freeze should return error")
	}
}

func TestFreezeController_UnfreezeWhenNotFrozenErrors(t *testing.T) {
	fc := NewFreezeController()
	_, err := fc.Unfreeze("admin")
	if err == nil {
		t.Fatal("unfreeze on unfrozen should error")
	}
}

func TestFreezeController_FreezeUnfreezeCycle(t *testing.T) {
	fc := NewFreezeController().WithClock(fixedClk)
	_, _ = fc.Freeze("admin")
	_, _ = fc.Unfreeze("admin")
	if fc.IsFrozen() {
		t.Fatal("should be unfrozen after unfreeze")
	}
	if len(fc.Receipts()) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(fc.Receipts()))
	}
}

func TestFreezeController_ReceiptContentHashNonEmpty(t *testing.T) {
	fc := NewFreezeController().WithClock(fixedClk)
	r, _ := fc.Freeze("ops")
	if r.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestFreezeState_ReturnsPrincipal(t *testing.T) {
	fc := NewFreezeController().WithClock(fixedClk)
	_, _ = fc.Freeze("root")
	frozen, principal, _ := fc.FreezeState()
	if !frozen || principal != "root" {
		t.Fatalf("expected frozen by root, got frozen=%v principal=%s", frozen, principal)
	}
}

func TestContextGuard_MatchingFingerprintPasses(t *testing.T) {
	cg := NewContextGuardWithFingerprint("abc123")
	if err := cg.Validate("abc123"); err != nil {
		t.Fatalf("matching fingerprint should pass: %v", err)
	}
}

func TestContextGuard_MismatchReturnsError(t *testing.T) {
	cg := NewContextGuardWithFingerprint("abc123def456abc123def456abc123def456abc123def456abc123def456abc1")
	err := cg.Validate("000000000000000000000000000000000000000000000000000000000000000f")
	if err == nil {
		t.Fatal("mismatched fingerprint should error")
	}
	var mismatch *ContextMismatchError
	if ok := errorAs(err, &mismatch); !ok {
		t.Fatalf("expected ContextMismatchError, got %T", err)
	}
}

func TestContextGuard_EmptyBootIsPassthrough(t *testing.T) {
	cg := NewContextGuardWithFingerprint("")
	if err := cg.Validate("anything"); err != nil {
		t.Fatalf("empty boot fingerprint should be passthrough: %v", err)
	}
}

func TestContextGuard_StatsTrackValidations(t *testing.T) {
	cg := NewContextGuardWithFingerprint("abc123def456abc123def456abc123def456abc123def456abc123def456abc1")
	_ = cg.Validate("abc123def456abc123def456abc123def456abc123def456abc123def456abc1")
	_ = cg.Validate("wrong00000000000000000000000000000000000000000000000000000000000")
	v, m := cg.Stats()
	if v != 2 || m != 1 {
		t.Fatalf("expected 2 validations 1 mismatch, got %d/%d", v, m)
	}
}

func TestContextGuard_ValidateCurrentDoesNotPanic(t *testing.T) {
	cg := NewContextGuard()
	_ = cg.ValidateCurrent()
}

// errorAs is a simple helper matching errors.As without importing errors.
func errorAs(err error, target interface{}) bool {
	if e, ok := err.(*ContextMismatchError); ok {
		if p, ok2 := target.(**ContextMismatchError); ok2 {
			*p = e
			return true
		}
	}
	return false
}
