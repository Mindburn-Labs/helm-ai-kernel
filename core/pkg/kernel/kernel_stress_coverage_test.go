package kernel

import (
	"fmt"

	"testing"
	"time"
)

// ── CSNF 100 Unicode strings ────────────────────────────────────────────

// Generate 100 by repeating patterns with indices

// ── Scheduler 500 concurrent events ─────────────────────────────────────

// ── Freeze/Unfreeze 1000 cycles ─────────────────────────────────────────

func TestStress_FreezeUnfreeze1000Cycles(t *testing.T) {
	fc := NewFreezeController()
	for i := range 1000 {
		_, err := fc.Freeze(fmt.Sprintf("admin-%d", i))
		if err != nil {
			t.Fatalf("freeze %d: %v", i, err)
		}
		if !fc.IsFrozen() {
			t.Fatalf("should be frozen at %d", i)
		}
		_, err = fc.Unfreeze(fmt.Sprintf("admin-%d", i))
		if err != nil {
			t.Fatalf("unfreeze %d: %v", i, err)
		}
		if fc.IsFrozen() {
			t.Fatalf("should not be frozen at %d", i)
		}
	}
	receipts := fc.Receipts()
	if len(receipts) != 2000 {
		t.Fatalf("expected 2000 receipts, got %d", len(receipts))
	}
}

func TestStress_ContextGuard50Fingerprints(t *testing.T) {
	bootFP := "boot-fingerprint-abc123"
	cg := NewContextGuardWithFingerprint(bootFP)
	for i := range 50 {
		fp := fmt.Sprintf("fp-%d", i)
		err := cg.Validate(fp)
		if err == nil {
			t.Fatalf("mismatch should fail for fp-%d", i)
		}
	}
	if err := cg.Validate(bootFP); err != nil {
		t.Fatalf("boot fingerprint should pass: %v", err)
	}
}

func TestStress_ContextGuardStats(t *testing.T) {
	cg := NewContextGuardWithFingerprint("boot")
	for range 30 {
		_ = cg.Validate("wrong")
	}
	for range 20 {
		_ = cg.Validate("boot")
	}
	validations, mismatches := cg.Stats()
	if validations != 50 {
		t.Fatalf("expected 50 validations, got %d", validations)
	}
	if mismatches != 30 {
		t.Fatalf("expected 30 mismatches, got %d", mismatches)
	}
}

func TestStress_ContextGuardEmptyBootPassThrough(t *testing.T) {
	cg := NewContextGuardWithFingerprint("")
	if err := cg.Validate("anything"); err != nil {
		t.Fatalf("empty boot FP should pass: %v", err)
	}
}

func TestStress_AgentKillSwitch100Agents(t *testing.T) {
	ks := NewAgentKillSwitch()
	for i := range 100 {
		agentID := fmt.Sprintf("agent-%d", i)
		_, err := ks.Kill(agentID, "admin", "test kill")
		if err != nil {
			t.Fatalf("kill %s: %v", agentID, err)
		}
		if !ks.IsKilled(agentID) {
			t.Fatalf("%s should be killed", agentID)
		}
	}
	for i := range 100 {
		agentID := fmt.Sprintf("agent-%d", i)
		_, err := ks.Revive(agentID, "admin")
		if err != nil {
			t.Fatalf("revive %s: %v", agentID, err)
		}
		if ks.IsKilled(agentID) {
			t.Fatalf("%s should be alive", agentID)
		}
	}
	receipts := ks.Receipts()
	if len(receipts) != 200 {
		t.Fatalf("expected 200 receipts, got %d", len(receipts))
	}
}

func TestStress_AgentKillSwitchDoubleKill(t *testing.T) {
	ks := NewAgentKillSwitch()
	_, _ = ks.Kill("a1", "admin", "first")
	_, err := ks.Kill("a1", "admin", "second")
	if err == nil {
		t.Fatal("double kill should fail")
	}
}

func TestStress_AgentKillSwitchDoubleRevive(t *testing.T) {
	ks := NewAgentKillSwitch()
	_, err := ks.Revive("a1", "admin")
	if err == nil {
		t.Fatal("reviving non-killed agent should fail")
	}
}

func TestStress_AgentKillSwitchListKilled(t *testing.T) {
	ks := NewAgentKillSwitch()
	for i := range 10 {
		_, _ = ks.Kill(fmt.Sprintf("a-%d", i), "admin", "test")
	}
	killed := ks.ListKilled()
	if len(killed) != 10 {
		t.Fatalf("expected 10 killed, got %d", len(killed))
	}
}

func TestStress_AgentKillReceiptHash(t *testing.T) {
	ks := NewAgentKillSwitch()
	receipt, _ := ks.Kill("a1", "admin", "reason")
	if receipt.ContentHash == "" {
		t.Fatal("receipt should have content hash")
	}
}

func TestStress_FreezeDoubleFreeze(t *testing.T) {
	fc := NewFreezeController()
	_, _ = fc.Freeze("admin")
	_, err := fc.Freeze("admin")
	if err == nil {
		t.Fatal("double freeze should fail")
	}
}

func TestStress_UnfreezeWhenNotFrozen(t *testing.T) {
	fc := NewFreezeController()
	_, err := fc.Unfreeze("admin")
	if err == nil {
		t.Fatal("unfreeze when not frozen should fail")
	}
}

func TestStress_FreezeState(t *testing.T) {
	fc := NewFreezeController()
	_, _ = fc.Freeze("admin")
	frozen, principal, at := fc.FreezeState()
	if !frozen || principal != "admin" || at.IsZero() {
		t.Fatal("freeze state mismatch")
	}
}

func TestStress_FreezeReceiptContentHash(t *testing.T) {
	fc := NewFreezeController()
	receipt, _ := fc.Freeze("admin")
	if receipt.ContentHash == "" {
		t.Fatal("freeze receipt should have content hash")
	}
}

func TestStress_FreezeWithClockOverride(t *testing.T) {
	fc := NewFreezeController()
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fc.WithClock(func() time.Time { return fixedTime })
	receipt, _ := fc.Freeze("admin")
	if !receipt.Timestamp.Equal(fixedTime) {
		t.Fatal("clock override not applied")
	}
}

func TestStress_ContextGuardMismatchError(t *testing.T) {
	cg := NewContextGuardWithFingerprint("aabbccdd112233445566778899001122")
	err := cg.Validate("different-fingerprint-xxxxxxxxxxxxxx")
	if err == nil {
		t.Fatal("should return mismatch error")
	}
	if _, ok := err.(*ContextMismatchError); !ok {
		t.Fatalf("expected ContextMismatchError, got %T", err)
	}
}

func TestStress_FreezeControllerReceiptsEmpty(t *testing.T) {
	fc := NewFreezeController()
	if len(fc.Receipts()) != 0 {
		t.Fatal("new controller should have 0 receipts")
	}
}

func TestStress_AgentKillSwitchClock(t *testing.T) {
	ks := NewAgentKillSwitch()
	fixed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	ks.WithKillSwitchClock(func() time.Time { return fixed })
	r, _ := ks.Kill("a1", "admin", "test")
	if !r.Timestamp.Equal(fixed) {
		t.Fatal("clock override not applied to kill switch")
	}
}
