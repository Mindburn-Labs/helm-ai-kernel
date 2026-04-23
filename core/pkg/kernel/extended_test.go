package kernel

import (
	"sync"
	"testing"
	"time"
)

// ─── 1: DependencyGraph hash determinism with unicode node IDs ─

func TestExt_DependencyGraphUnicodeNodeID(t *testing.T) {
	g1 := NewDependencyGraph("g1", "r1")
	g1.AddNode(DependencyNode{NodeID: "noeud-\u00e9", NodeType: "data", ContentHash: "h1"})
	g1.Finalize()
	g2 := NewDependencyGraph("g2", "r1")
	g2.AddNode(DependencyNode{NodeID: "noeud-\u00e9", NodeType: "data", ContentHash: "h1"})
	g2.Finalize()
	if g1.Hash != g2.Hash {
		t.Fatal("same unicode node should produce same hash")
	}
}

// ─── 2: DependencyGraph hash changes with different content ───

func TestExt_DependencyGraphHashChangesOnContent(t *testing.T) {
	g1 := NewDependencyGraph("g1", "r1")
	g1.AddNode(DependencyNode{NodeID: "n1", NodeType: "data", ContentHash: "h1"})
	g1.Finalize()
	g2 := NewDependencyGraph("g2", "r1")
	g2.AddNode(DependencyNode{NodeID: "n1", NodeType: "data", ContentHash: "h2"})
	g2.Finalize()
	if g1.Hash == g2.Hash {
		t.Fatal("different content hashes should produce different graph hashes")
	}
}

// ─── 3: DependencyGraph Finalize identifies roots and leaves ──

func TestExt_DependencyGraphRootsAndLeaves(t *testing.T) {
	g := NewDependencyGraph("g1", "r1")
	g.AddNode(DependencyNode{NodeID: "a"})
	g.AddNode(DependencyNode{NodeID: "b"})
	g.AddEdge("a", "b", "DATA")
	g.Finalize()
	if len(g.RootNodes) != 1 || g.RootNodes[0] != "a" {
		t.Fatalf("expected root [a], got %v", g.RootNodes)
	}
	if len(g.LeafNodes) != 1 || g.LeafNodes[0] != "b" {
		t.Fatalf("expected leaf [b], got %v", g.LeafNodes)
	}
}

// ─── 4: RetrySchedule — equal timestamps produce same delay ──

func TestExt_RetryScheduleEqualTimestamps(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rs := NewRetrySchedule("s1", "op1", RetryStrategyFixed, 100, 1000, 1.0)
	t1 := rs.ScheduleNextRun(base, 0)
	t2 := rs.ScheduleNextRun(base, 0)
	if !t1.Equal(t2) {
		t.Fatal("same base time and attempt should produce same schedule")
	}
}

// ─── 5: RetrySchedule — exponential caps at max ──────────────

func TestExt_RetryScheduleExponentialCapsMax(t *testing.T) {
	rs := NewRetrySchedule("s1", "op1", RetryStrategyExponential, 100, 500, 2.0)
	delay := rs.ComputeDelay(10) // 100 * 2^10 = 102400, capped at 500
	if delay != 500 {
		t.Fatalf("expected 500 (capped), got %d", delay)
	}
}

// ─── 6: RetrySchedule — linear delay ─────────────────────────

func TestExt_RetryScheduleLinear(t *testing.T) {
	rs := NewRetrySchedule("s1", "op1", RetryStrategyLinear, 100, 10000, 1.0)
	if d := rs.ComputeDelay(4); d != 500 {
		t.Fatalf("expected linear delay 500, got %d", d)
	}
}

// ─── 7: RetrySchedule — unknown strategy defaults to base ────

func TestExt_RetryScheduleUnknownStrategy(t *testing.T) {
	rs := NewRetrySchedule("s1", "op1", RetryStrategy("UNKNOWN"), 100, 1000, 1.0)
	if d := rs.ComputeDelay(5); d != 100 {
		t.Fatalf("unknown strategy should use base delay, got %d", d)
	}
}

// ─── 8: NondeterminismTracker — all sources captured ──────────

func TestExt_NondeterminismAllSources(t *testing.T) {
	tracker := NewNondeterminismTracker()
	sources := []NondeterminismSource{NDSourceLLM, NDSourceNetwork, NDSourceRandom, NDSourceExternal, NDSourceTiming, NDSourceUserInput}
	for _, src := range sources {
		tracker.Capture("run-1", src, "test", "in", "out", "")
	}
	bounds := tracker.BoundsForRun("run-1")
	if len(bounds) != 6 {
		t.Fatalf("expected 6 bounds, got %d", len(bounds))
	}
}

// ─── 9: NondeterminismTracker — Receipt for unknown run ───────

func TestExt_NondeterminismReceiptUnknownRun(t *testing.T) {
	tracker := NewNondeterminismTracker()
	_, err := tracker.Receipt("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown run")
	}
}

// ─── 10: NondeterminismTracker — Receipt content hash ─────────

func TestExt_NondeterminismReceiptHash(t *testing.T) {
	tracker := NewNondeterminismTracker()
	tracker.Capture("run-1", NDSourceLLM, "test", "in", "out", "")
	receipt, _ := tracker.Receipt("run-1")
	if receipt.ContentHash == "" {
		t.Fatal("receipt content hash should be non-empty")
	}
}

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

// ─── 12: FreezeController — concurrent toggle ────────────────

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

// ─── 13: FreezeController — FreezeState returns details ───────

func TestExt_FreezeStateDetails(t *testing.T) {
	fc := NewFreezeController()
	fc.Freeze("admin-1")
	isFrozen, principal, ts := fc.FreezeState()
	if !isFrozen || principal != "admin-1" || ts.IsZero() {
		t.Fatalf("unexpected state: frozen=%v principal=%s ts=%v", isFrozen, principal, ts)
	}
}

// ─── 14: ContextGuard — empty boot fingerprint passes ─────────

func TestExt_ContextGuardEmptyBootPasses(t *testing.T) {
	cg := NewContextGuardWithFingerprint("")
	if err := cg.Validate("anything"); err != nil {
		t.Fatalf("empty boot fingerprint should pass, got %v", err)
	}
}

// ─── 15: ContextGuard — matching fingerprint passes ───────────

func TestExt_ContextGuardMatchingPasses(t *testing.T) {
	cg := NewContextGuardWithFingerprint("fp-123")
	if err := cg.Validate("fp-123"); err != nil {
		t.Fatalf("matching fingerprint should pass, got %v", err)
	}
}

// ─── 16: ContextGuard — mismatch returns error type ───────────

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

// ─── 17: ContextGuard — stats track validations ──────────────

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

// ─── 18: ContextGuard — env change detection ─────────────────

func TestExt_ContextGuardBootFingerprint(t *testing.T) {
	cg := NewContextGuard()
	fp := cg.BootFingerprint()
	if fp == "" {
		t.Fatal("boot fingerprint should be non-empty")
	}
}

// ─── 19: AttemptIndex — CanRetry respects max ─────────────────

func TestExt_AttemptIndexCanRetry(t *testing.T) {
	idx := NewAttemptIndex("i1", "op1", 2)
	if !idx.CanRetry() {
		t.Fatal("should be able to retry initially")
	}
	idx.RecordAttempt(false, "ERR", "fail")
	idx.RecordAttempt(false, "ERR", "fail")
	if idx.CanRetry() {
		t.Fatal("should not be able to retry after max attempts")
	}
}

// ─── 20: AttemptIndex — LastAttempt returns nil when empty ────

func TestExt_AttemptIndexLastAttemptNil(t *testing.T) {
	idx := NewAttemptIndex("i1", "op1", 5)
	if idx.LastAttempt() != nil {
		t.Fatal("expected nil for empty attempts")
	}
}

// ─── 21: AttemptIndex — error hash computed ───────────────────

func TestExt_AttemptIndexErrorHash(t *testing.T) {
	idx := NewAttemptIndex("i1", "op1", 5)
	idx.RecordAttempt(false, "ERR", "some error")
	last := idx.LastAttempt()
	if last.ErrorHash == "" {
		t.Fatal("error hash should be non-empty when error message present")
	}
}

// ─── 22: ExecutionTrace — VerifyDeterminism ───────────────────

func TestExt_ExecutionTraceVerifyDeterminism(t *testing.T) {
	t1 := NewExecutionTrace("t1", "r1")
	t1.AddEntry("e1", "TOOL_CALL", "in1", "out1")
	t2 := NewExecutionTrace("t2", "r1")
	t2.AddEntry("e1", "TOOL_CALL", "in1", "out1")
	if !t1.VerifyDeterminism(t2) {
		t.Fatal("identical traces should verify as deterministic")
	}
}

// ─── 23: ExecutionTrace — different traces fail verify ────────

func TestExt_ExecutionTraceDifferentFails(t *testing.T) {
	t1 := NewExecutionTrace("t1", "r1")
	t1.AddEntry("e1", "TOOL_CALL", "in1", "out1")
	t2 := NewExecutionTrace("t2", "r1")
	t2.AddEntry("e2", "TOOL_CALL", "in1", "out1")
	if t1.VerifyDeterminism(t2) {
		t.Fatal("different traces should not verify as deterministic")
	}
}

// ─── 24: ValidateConcurrencyArtifact — unknown type ───────────

func TestExt_ValidateConcurrencyArtifactUnknown(t *testing.T) {
	art := &ConcurrencyArtifact{Type: ConcurrencyArtifactType("UNKNOWN")}
	issues := ValidateConcurrencyArtifact(art)
	if len(issues) == 0 {
		t.Fatal("expected issues for unknown type")
	}
}

// ─── 25: ValidateConcurrencyArtifact — nil dependency graph ───

func TestExt_ValidateArtifactNilDependencyGraph(t *testing.T) {
	art := &ConcurrencyArtifact{Type: ConcurrencyArtifactDependencyGraph}
	issues := ValidateConcurrencyArtifact(art)
	if len(issues) == 0 {
		t.Fatal("expected issues for nil dependency graph")
	}
}
