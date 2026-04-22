package kernel

import (
	"testing"
	"time"
)

func TestContextGuard_BootFingerprint(t *testing.T) {
	cg := NewContextGuard()
	fp := cg.BootFingerprint()
	if fp == "" {
		t.Error("boot fingerprint must not be empty")
	}
	if len(fp) != 64 { // SHA-256 hex
		t.Errorf("boot fingerprint length = %d, want 64 hex chars", len(fp))
	}
}

func TestContextGuard_ValidateMatch(t *testing.T) {
	cg := NewContextGuardWithFingerprint("abc123")
	err := cg.Validate("abc123")
	if err != nil {
		t.Errorf("matching fingerprint should pass, got: %v", err)
	}
}

func TestContextGuard_ValidateMismatch(t *testing.T) {
	ts := time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC)
	cg := NewContextGuardWithFingerprint("boot-fingerprint-aaa")
	cg.WithClock(fixedClock(ts))

	err := cg.Validate("different-fingerprint-bbb")
	if err == nil {
		t.Fatal("mismatched fingerprint should return error")
	}

	mismatch, ok := err.(*ContextMismatchError)
	if !ok {
		t.Fatalf("error should be *ContextMismatchError, got %T", err)
	}
	if mismatch.BootFingerprint != "boot-fingerprint-aaa" {
		t.Errorf("boot = %s, want boot-fingerprint-aaa", mismatch.BootFingerprint)
	}
	if mismatch.CurrentFingerprint != "different-fingerprint-bbb" {
		t.Errorf("current = %s, want different-fingerprint-bbb", mismatch.CurrentFingerprint)
	}
}

func TestContextGuard_EmptyBootPassthrough(t *testing.T) {
	cg := NewContextGuardWithFingerprint("")
	err := cg.Validate("any-fingerprint")
	if err != nil {
		t.Errorf("empty boot fingerprint should pass-through, got: %v", err)
	}
}

func TestContextGuard_ValidateCurrentSameEnvironment(t *testing.T) {
	cg := NewContextGuard()
	err := cg.ValidateCurrent()
	if err != nil {
		t.Errorf("ValidateCurrent in same env should pass, got: %v", err)
	}
}

func TestContextGuard_Stats(t *testing.T) {
	cg := NewContextGuardWithFingerprint("fp1")

	cg.Validate("fp1") // match
	cg.Validate("fp2") // mismatch
	cg.Validate("fp1") // match
	cg.Validate("fp3") // mismatch

	validations, mismatches := cg.Stats()
	if validations != 4 {
		t.Errorf("validations = %d, want 4", validations)
	}
	if mismatches != 2 {
		t.Errorf("mismatches = %d, want 2", mismatches)
	}
}

func TestContextGuard_DeterministicFingerprint(t *testing.T) {
	cg1 := NewContextGuard()
	cg2 := NewContextGuard()
	if cg1.BootFingerprint() != cg2.BootFingerprint() {
		t.Error("two guards created in same environment should have same fingerprint")
	}
}
