package kernel

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── CSNF Tests ───────────────────────────────────────────────────

func TestDeepCSNFTransformNilPreserved(t *testing.T) {
	tr := NewCSNFTransformer()
	result, err := tr.Transform(nil)
	if err != nil || result != nil {
		t.Fatal("nil should be preserved")
	}
}

func TestDeepCSNFTransformStringNFC(t *testing.T) {
	tr := NewCSNFTransformer()
	// e-acute as combining sequence (e + combining acute)
	result, err := tr.Transform("e\u0301")
	if err != nil {
		t.Fatal(err)
	}
	if result != "\u00e9" {
		t.Fatalf("expected NFC normalized e-acute, got %q", result)
	}
}

func TestDeepCSNFTransformASCIIUnchanged(t *testing.T) {
	tr := NewCSNFTransformer()
	result, _ := tr.Transform("hello world")
	if result != "hello world" {
		t.Fatal("ASCII should be unchanged")
	}
}

func TestDeepCSNFTransformEmptyString(t *testing.T) {
	tr := NewCSNFTransformer()
	result, _ := tr.Transform("")
	if result != "" {
		t.Fatal("empty string should be preserved")
	}
}

func TestDeepCSNFTransformNumber(t *testing.T) {
	tr := NewCSNFTransformer()
	result, _ := tr.Transform(42.0)
	// CSNF converts integer-valued floats to int (42.0 -> 42)
	if fmt.Sprintf("%v", result) != "42" {
		t.Fatalf("integer-valued float should normalize to 42, got %v", result)
	}
}

func TestDeepCSNFTransformMapSortedKeys(t *testing.T) {
	tr := NewCSNFTransformer()
	input := map[string]any{"z": 1, "a": 2, "m": 3}
	result, err := tr.Transform(input)
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if m["z"] != 1 || m["a"] != 2 {
		t.Fatal("map values should be preserved")
	}
}

func TestDeepCSNFTransformDeterministic(t *testing.T) {
	tr := NewCSNFTransformer()
	input := map[string]any{"key": "caf\u0065\u0301"}
	r1, _ := tr.Transform(input)
	r2, _ := tr.Transform(input)
	m1 := r1.(map[string]any)
	m2 := r2.(map[string]any)
	if m1["key"] != m2["key"] {
		t.Fatal("same input should produce identical output")
	}
}

func TestDeepCSNFTransformUnicodeHangul(t *testing.T) {
	tr := NewCSNFTransformer()
	// Hangul syllable composed from jamo
	result, _ := tr.Transform("\u1100\u1161") // ㄱ + ㅏ → 가
	if result != "\uAC00" {
		t.Fatalf("Hangul jamo should compose to syllable, got %q", result)
	}
}

// ── Scheduler Tests ──────────────────────────────────────────────

func TestDeepSchedulerPriorityOrdering(t *testing.T) {
	s := NewInMemoryScheduler()
	ctx := context.Background()
	now := time.Now()
	s.Schedule(ctx, &SchedulerEvent{EventID: "low", ScheduledAt: now, Priority: 10})
	s.Schedule(ctx, &SchedulerEvent{EventID: "high", ScheduledAt: now, Priority: 1})
	e, _ := s.Next(ctx)
	if e.EventID != "high" {
		t.Fatal("higher priority (lower number) should come first")
	}
}

func TestDeepSchedulerTimeOrdering(t *testing.T) {
	s := NewInMemoryScheduler()
	ctx := context.Background()
	t1 := time.Now()
	t2 := t1.Add(time.Second)
	s.Schedule(ctx, &SchedulerEvent{EventID: "later", ScheduledAt: t2})
	s.Schedule(ctx, &SchedulerEvent{EventID: "earlier", ScheduledAt: t1})
	e, _ := s.Next(ctx)
	if e.EventID != "earlier" {
		t.Fatal("earlier scheduled event should come first")
	}
}

func TestDeepScheduler1000Events(t *testing.T) {
	s := NewInMemoryScheduler()
	ctx := context.Background()
	base := time.Now()
	for i := 0; i < 1000; i++ {
		s.Schedule(ctx, &SchedulerEvent{
			EventID:     fmt.Sprintf("evt-%d", i),
			ScheduledAt: base.Add(time.Duration(999-i) * time.Millisecond),
			Priority:    i % 5,
		})
	}
	if s.Len() != 1000 {
		t.Fatalf("expected 1000 events, got %d", s.Len())
	}
	// Drain and verify monotonicity of scheduling order
	var prev *SchedulerEvent
	for i := 0; i < 1000; i++ {
		e, err := s.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if prev != nil && e.ScheduledAt.Before(prev.ScheduledAt) {
			t.Fatalf("event %d scheduled before event %d", i, i-1)
		}
		prev = e
	}
}

func TestDeepSchedulerSnapshotHashDeterministic(t *testing.T) {
	s := NewInMemoryScheduler()
	ctx := context.Background()
	now := time.Now()
	s.Schedule(ctx, &SchedulerEvent{EventID: "a", ScheduledAt: now})
	s.Schedule(ctx, &SchedulerEvent{EventID: "b", ScheduledAt: now.Add(time.Second)})
	h1 := s.SnapshotHash()
	h2 := s.SnapshotHash()
	if h1 != h2 {
		t.Fatal("snapshot hash should be deterministic")
	}
}

func TestDeepSchedulerPeekDoesNotConsume(t *testing.T) {
	s := NewInMemoryScheduler()
	ctx := context.Background()
	s.Schedule(ctx, &SchedulerEvent{EventID: "peek-me", ScheduledAt: time.Now()})
	e, _ := s.Peek(ctx)
	if e == nil || e.EventID != "peek-me" {
		t.Fatal("peek should return the next event")
	}
	if s.Len() != 1 {
		t.Fatal("peek should not remove the event")
	}
}

func TestDeepSchedulerClose(t *testing.T) {
	s := NewInMemoryScheduler()
	s.Close()
	err := s.Schedule(context.Background(), &SchedulerEvent{EventID: "x"})
	if err != ErrSchedulerClosed {
		t.Fatal("schedule on closed scheduler should return ErrSchedulerClosed")
	}
}

// ── Nondeterminism Tracker Tests ─────────────────────────────────

func TestDeepNondeterminismTrackerAllSources(t *testing.T) {
	tracker := NewNondeterminismTracker()
	sources := []NondeterminismSource{NDSourceLLM, NDSourceNetwork, NDSourceRandom, NDSourceExternal, NDSourceTiming, NDSourceUserInput}
	for _, s := range sources {
		tracker.Capture("run-1", s, "test", "in", "out", "seed")
	}
	receipt, err := tracker.Receipt("run-1")
	if err != nil || receipt.TotalBounds != 6 {
		t.Fatalf("expected 6 bounds, got %d", receipt.TotalBounds)
	}
}

func TestDeepNondeterminismTrackerReceiptUnknownRun(t *testing.T) {
	tracker := NewNondeterminismTracker()
	_, err := tracker.Receipt("nonexistent")
	if err == nil {
		t.Fatal("should error for unknown run")
	}
}

func TestDeepNondeterminismTrackerBoundIDUnique(t *testing.T) {
	tracker := NewNondeterminismTracker()
	ids := map[string]bool{}
	for i := 0; i < 100; i++ {
		b := tracker.Capture("run-1", NDSourceRandom, "d", "i", "o", "s")
		if ids[b.BoundID] {
			t.Fatalf("duplicate bound ID: %s", b.BoundID)
		}
		ids[b.BoundID] = true
	}
}

func TestDeepNondeterminismReceiptHashDeterministic(t *testing.T) {
	clk := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := NewNondeterminismTracker().WithClock(func() time.Time { return clk })
	t2 := NewNondeterminismTracker().WithClock(func() time.Time { return clk })
	t1.Capture("r", NDSourceLLM, "d", "i", "o", "s")
	t2.Capture("r", NDSourceLLM, "d", "i", "o", "s")
	r1, _ := t1.Receipt("r")
	r2, _ := t2.Receipt("r")
	if r1.ContentHash != r2.ContentHash {
		t.Fatal("same inputs should produce same receipt hash")
	}
}

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

// ── AgentKillSwitch Tests ────────────────────────────────────────

func TestDeepAgentKillSwitchKillRevive(t *testing.T) {
	ks := NewAgentKillSwitch()
	_, err := ks.Kill("agent-1", "admin", "testing")
	if err != nil || !ks.IsKilled("agent-1") {
		t.Fatal("kill should succeed")
	}
	_, err = ks.Revive("agent-1", "admin")
	if err != nil || ks.IsKilled("agent-1") {
		t.Fatal("revive should succeed")
	}
}

func TestDeepAgentKillSwitchDoubleKill(t *testing.T) {
	ks := NewAgentKillSwitch()
	ks.Kill("a", "admin", "test")
	_, err := ks.Kill("a", "admin", "test")
	if err == nil {
		t.Fatal("double kill should error")
	}
}

func TestDeepAgentKillSwitchReviveNonKilled(t *testing.T) {
	ks := NewAgentKillSwitch()
	_, err := ks.Revive("not-killed", "admin")
	if err == nil {
		t.Fatal("revive non-killed agent should error")
	}
}

func TestDeepAgentKillSwitchConcurrent(t *testing.T) {
	ks := NewAgentKillSwitch()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			agent := fmt.Sprintf("agent-%d", idx%20)
			switch idx % 3 {
			case 0:
				ks.Kill(agent, "admin", "test")
			case 1:
				ks.Revive(agent, "admin")
			case 2:
				ks.IsKilled(agent)
			}
		}(i)
	}
	wg.Wait()
}

func TestDeepAgentKillSwitchListKilled(t *testing.T) {
	ks := NewAgentKillSwitch()
	ks.Kill("a", "admin", "r1")
	ks.Kill("b", "admin", "r2")
	ks.Kill("c", "admin", "r3")
	killed := ks.ListKilled()
	if len(killed) != 3 {
		t.Fatalf("expected 3 killed, got %d", len(killed))
	}
}

// ── PRNG Tests ───────────────────────────────────────────────────

func TestDeepPRNGConstruction(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	cfg := DefaultPRNGConfig()
	log := NewInMemoryEventLog()
	p, err := NewDeterministicPRNG(cfg, seed, "loop-1", log)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("nil PRNG")
	}
}

func TestDeepPRNGSeedLengthMismatch(t *testing.T) {
	_, err := NewDeterministicPRNG(DefaultPRNGConfig(), []byte{1, 2, 3}, "l", nil)
	if err == nil {
		t.Fatal("mismatched seed length should error")
	}
}

func TestDeepDeriveSeedDeterministic(t *testing.T) {
	parent := make([]byte, 32)
	s1 := DeriveSeed(parent, "child-1")
	s2 := DeriveSeed(parent, "child-1")
	if string(s1) != string(s2) {
		t.Fatal("same derivation input should produce same seed")
	}
	s3 := DeriveSeed(parent, "child-2")
	if string(s1) == string(s3) {
		t.Fatal("different derivation inputs should produce different seeds")
	}
}
