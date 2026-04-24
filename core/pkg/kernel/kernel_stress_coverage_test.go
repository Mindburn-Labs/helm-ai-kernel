package kernel

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── CSNF 100 Unicode strings ────────────────────────────────────────────

func TestStress_CSNF100Unicode(t *testing.T) {
	transformer := NewCSNFTransformer()
	unicodeStrings := []string{
		"Hello", "Héllo", "日本語", "中文", "العربية", "हिन्दी", "한국어", "Ελληνικά",
		"\u00e9", "\u00f1", "\u00fc", "\u00e0", "café", "naïve", "résumé", "über",
		"emoji: 🎉", "combined: é", "zwnj:\u200c", "zwj:\u200d",
	}
	// Generate 100 by repeating patterns with indices
	for i := range 100 {
		input := unicodeStrings[i%len(unicodeStrings)] + fmt.Sprintf("-%d", i)
		result, err := transformer.Transform(input)
		if err != nil {
			t.Fatalf("CSNF failed for %q: %v", input, err)
		}
		if result == nil {
			t.Fatalf("CSNF returned nil for %q", input)
		}
	}
}

// ── Scheduler 500 concurrent events ─────────────────────────────────────

func TestStress_Scheduler500ConcurrentEvents(t *testing.T) {
	scheduler := NewInMemoryScheduler()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 500 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = scheduler.Schedule(ctx, &SchedulerEvent{
				EventID:     fmt.Sprintf("evt-%d", idx),
				EventType:   "test",
				ScheduledAt: time.Now(),
				Priority:    idx % 10,
				SequenceNum: uint64(idx),
			})
		}(i)
	}
	wg.Wait()
	if scheduler.Len() != 500 {
		t.Fatalf("expected 500 events, got %d", scheduler.Len())
	}
}

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

// ── Context Guard 50 fingerprints ───────────────────────────────────────

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

// ── Agent Kill Switch: kill/revive 100 agents ───────────────────────────

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

// ── Nondeterminism Tracker: all 6 sources x 10 captures ────────────────

func TestStress_NondeterminismAllSources(t *testing.T) {
	tracker := NewNondeterminismTracker()
	sources := []NondeterminismSource{
		NDSourceLLM, NDSourceNetwork, NDSourceRandom,
		NDSourceExternal, NDSourceTiming, NDSourceUserInput,
	}
	for _, src := range sources {
		for j := range 10 {
			bound := tracker.Capture("run-1", src, fmt.Sprintf("desc-%d", j), "in-hash", "out-hash", "seed")
			if bound.Source != src {
				t.Fatalf("source mismatch: %s != %s", bound.Source, src)
			}
			if !strings.HasPrefix(bound.ContentHash, "sha256:") {
				t.Fatal("content hash missing sha256 prefix")
			}
		}
	}
	bounds := tracker.BoundsForRun("run-1")
	if len(bounds) != 60 {
		t.Fatalf("expected 60 bounds, got %d", len(bounds))
	}
}

func TestStress_NondeterminismReceipt(t *testing.T) {
	tracker := NewNondeterminismTracker()
	tracker.Capture("run-r", NDSourceLLM, "test", "in", "out", "")
	receipt, err := tracker.Receipt("run-r")
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if receipt.TotalBounds != 1 {
		t.Fatalf("expected 1 bound, got %d", receipt.TotalBounds)
	}
}

func TestStress_NondeterminismReceiptMissingRun(t *testing.T) {
	tracker := NewNondeterminismTracker()
	_, err := tracker.Receipt("nonexistent")
	if err == nil {
		t.Fatal("missing run should error")
	}
}

// ── FreezeController edge cases ─────────────────────────────────────────

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

// ── Scheduler deterministic ordering ────────────────────────────────────

func TestStress_SchedulerDeterministicOrder(t *testing.T) {
	scheduler := NewInMemoryScheduler()
	ctx := context.Background()
	now := time.Now()
	for i := range 100 {
		_ = scheduler.Schedule(ctx, &SchedulerEvent{
			EventID: fmt.Sprintf("e-%d", i), EventType: "test", ScheduledAt: now,
			Priority: 100 - i, SequenceNum: uint64(i),
		})
	}
	prev := -1
	for range 100 {
		evt, _ := scheduler.Next(ctx)
		if prev >= evt.Priority {
			// Priority should be ascending (lower number = higher priority)
			if prev > evt.Priority {
				t.Fatalf("order violated: prev=%d, current=%d", prev, evt.Priority)
			}
		}
		prev = evt.Priority
	}
}

func TestStress_SchedulerSnapshotHash(t *testing.T) {
	scheduler := NewInMemoryScheduler()
	ctx := context.Background()
	_ = scheduler.Schedule(ctx, &SchedulerEvent{EventID: "e1", ScheduledAt: time.Now()})
	h1 := scheduler.SnapshotHash()
	h2 := scheduler.SnapshotHash()
	if h1 != h2 {
		t.Fatal("snapshot hash should be deterministic")
	}
}

// ── CSNF deterministic hash ─────────────────────────────────────────────

func TestStress_CSNFDeterministicHash(t *testing.T) {
	transformer := NewCSNFTransformer()
	for range 50 {
		r1, _ := transformer.Transform(map[string]any{"b": 2, "a": 1})
		r2, _ := transformer.Transform(map[string]any{"a": 1, "b": 2})
		if fmt.Sprintf("%v", r1) != fmt.Sprintf("%v", r2) {
			t.Fatal("CSNF should produce same output regardless of key order")
		}
	}
}

func TestStress_CSNFWithArrayMeta(t *testing.T) {
	transformer := NewCSNFTransformer().WithArrayMeta("/tags", CSNFArrayMeta{Kind: CSNFArrayKindSet})
	result, err := transformer.Transform(map[string]any{"tags": []any{"b", "a", "c"}})
	if err != nil {
		t.Fatalf("CSNF with array meta: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
}

// ── NondeterminismSource constants ──────────────────────────────────────

func TestStress_NDSourceLLMValue(t *testing.T) {
	if NDSourceLLM != "LLM" {
		t.Fatalf("got %s", NDSourceLLM)
	}
}

func TestStress_NDSourceNetworkValue(t *testing.T) {
	if NDSourceNetwork != "NETWORK" {
		t.Fatalf("got %s", NDSourceNetwork)
	}
}

func TestStress_NDSourceRandomValue(t *testing.T) {
	if NDSourceRandom != "RANDOM" {
		t.Fatalf("got %s", NDSourceRandom)
	}
}

func TestStress_NDSourceExternalValue(t *testing.T) {
	if NDSourceExternal != "EXTERNAL_API" {
		t.Fatalf("got %s", NDSourceExternal)
	}
}

func TestStress_NDSourceTimingValue(t *testing.T) {
	if NDSourceTiming != "TIMING" {
		t.Fatalf("got %s", NDSourceTiming)
	}
}

func TestStress_NDSourceUserInputValue(t *testing.T) {
	if NDSourceUserInput != "USER_INPUT" {
		t.Fatalf("got %s", NDSourceUserInput)
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

func TestStress_CSNFProfileID(t *testing.T) {
	if CSNFProfileID != "csnf-v1" {
		t.Fatalf("got %s", CSNFProfileID)
	}
}

func TestStress_CanonicalProfileID(t *testing.T) {
	if CanonicalProfileID != "csnf-v1+jcs-v1" {
		t.Fatalf("got %s", CanonicalProfileID)
	}
}

func TestStress_CSNFArrayKindOrdered(t *testing.T) {
	if CSNFArrayKindOrdered != "ORDERED" {
		t.Fatalf("got %s", CSNFArrayKindOrdered)
	}
}

func TestStress_CSNFArrayKindSet(t *testing.T) {
	if CSNFArrayKindSet != "SET" {
		t.Fatalf("got %s", CSNFArrayKindSet)
	}
}

func TestStress_NondeterminismTrackerClock(t *testing.T) {
	fixed := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	tracker := NewNondeterminismTracker().WithClock(func() time.Time { return fixed })
	b := tracker.Capture("r1", NDSourceLLM, "d", "in", "out", "")
	if !b.CapturedAt.Equal(fixed) {
		t.Fatal("clock override not applied")
	}
}

func TestStress_FreezeControllerReceiptsEmpty(t *testing.T) {
	fc := NewFreezeController()
	if len(fc.Receipts()) != 0 {
		t.Fatal("new controller should have 0 receipts")
	}
}

func TestStress_SchedulerEmpty(t *testing.T) {
	scheduler := NewInMemoryScheduler()
	if scheduler.Len() != 0 {
		t.Fatal("new scheduler should have 0 events")
	}
}

func TestStress_SchedulerPeek(t *testing.T) {
	scheduler := NewInMemoryScheduler()
	ctx := context.Background()
	_ = scheduler.Schedule(ctx, &SchedulerEvent{EventID: "e1", ScheduledAt: time.Now()})
	evt, err := scheduler.Peek(ctx)
	if err != nil || evt == nil {
		t.Fatal("peek should return event")
	}
	if scheduler.Len() != 1 {
		t.Fatal("peek should not remove event")
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

func TestStress_NondeterminismMultipleRuns(t *testing.T) {
	tracker := NewNondeterminismTracker()
	tracker.Capture("run-a", NDSourceLLM, "d", "in", "out", "")
	tracker.Capture("run-b", NDSourceNetwork, "d", "in", "out", "")
	if len(tracker.BoundsForRun("run-a")) != 1 || len(tracker.BoundsForRun("run-b")) != 1 {
		t.Fatal("bounds should be separated per run")
	}
}
