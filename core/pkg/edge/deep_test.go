package edge

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var edgeTime = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

func baseConfig() EdgeConfig {
	return EdgeConfig{
		DeviceID: "dev-1",
		PolicyRules: []PolicyRule{
			{Action: "read", Verdict: "ALLOW", Reason: "read is safe"},
			{Action: "write", Verdict: "ALLOW", Reason: "write is safe"},
			{Action: "delete", Verdict: "DENY", Reason: "destructive"},
		},
		DefaultVerdict: "DENY",
		MaxQueueSize:   1000,
	}
}

func TestDeep_Guardian10000Decisions(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	g.WithClock(func() time.Time { return edgeTime })
	for i := 0; i < 10000; i++ {
		d := g.Evaluate("user", "read")
		if d.Verdict != "ALLOW" {
			t.Fatalf("decision %d: expected ALLOW, got %s", i, d.Verdict)
		}
	}
	if g.DecisionCount() != 10000 {
		t.Fatalf("expected 10000 decisions, got %d", g.DecisionCount())
	}
}

func TestDeep_Guardian10000UniqueDecisionIDs(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	seen := make(map[string]bool, 10000)
	for i := 0; i < 10000; i++ {
		d := g.Evaluate("u", "read")
		if seen[d.DecisionID] {
			t.Fatalf("duplicate DecisionID at %d: %s", i, d.DecisionID)
		}
		seen[d.DecisionID] = true
	}
}

func TestDeep_GuardianContentHashSet(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	d := g.Evaluate("u", "read")
	if d.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestDeep_GuardianDefaultDeny(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	d := g.Evaluate("u", "unknown_action")
	if d.Verdict != "DENY" {
		t.Fatalf("unknown action should DENY, got %s", d.Verdict)
	}
}

func TestDeep_GuardianAllowKnownAction(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	d := g.Evaluate("u", "read")
	if d.Verdict != "ALLOW" {
		t.Fatal("read should be allowed")
	}
}

func TestDeep_GuardianDenyDestructiveAction(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	d := g.Evaluate("u", "delete")
	if d.Verdict != "DENY" {
		t.Fatal("delete should be denied")
	}
}

func TestDeep_QueueOverflowBehavior(t *testing.T) {
	cfg := baseConfig()
	cfg.MaxQueueSize = 5
	g := NewEdgeGuardian(cfg)

	for i := 0; i < 5; i++ {
		d := g.Evaluate("u", "read")
		if d.QueueFull {
			t.Fatalf("queue should not be full at decision %d", i)
		}
	}

	d := g.Evaluate("u", "read")
	if !d.QueueFull {
		t.Fatal("6th decision should see QueueFull=true")
	}

	if g.QueueSize() != 5 {
		t.Fatalf("queue should remain at max size, got %d", g.QueueSize())
	}
}

func TestDeep_QueueOverflowStillDecides(t *testing.T) {
	cfg := baseConfig()
	cfg.MaxQueueSize = 1
	g := NewEdgeGuardian(cfg)
	g.Evaluate("u", "read") // fills queue
	d := g.Evaluate("u", "read")
	if d.Verdict != "ALLOW" {
		t.Fatal("decisions should still work even with full queue")
	}
}

func TestDeep_RuleUpdateUnderLoad(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	var wg sync.WaitGroup
	var denyCount atomic.Int64

	// Start load
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				d := g.Evaluate("u", "special")
				if d.Verdict == "DENY" {
					denyCount.Add(1)
				}
			}
		}()
	}

	// Update rules mid-flight
	g.UpdateRules([]PolicyRule{
		{Action: "special", Verdict: "ALLOW", Reason: "now allowed"},
	})

	wg.Wait()
	// Some decisions should have been DENY (before update) and some ALLOW (after)
	// We just verify no panics and total decisions match
	if g.DecisionCount() != 1000 {
		t.Fatalf("expected 1000 decisions, got %d", g.DecisionCount())
	}
}

func TestDeep_FlushQueueReturnsAll(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	for i := 0; i < 10; i++ {
		g.Evaluate("u", "read")
	}
	flushed := g.FlushQueue()
	if len(flushed) != 10 {
		t.Fatalf("expected 10 flushed, got %d", len(flushed))
	}
	if g.QueueSize() != 0 {
		t.Fatal("queue should be empty after flush")
	}
}

func TestDeep_FlushEmptyQueue(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	flushed := g.FlushQueue()
	if len(flushed) != 0 {
		t.Fatal("flushing empty queue should return empty slice")
	}
}

func TestDeep_SyncManagerWithFailingSink(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	g.Evaluate("u", "read")

	failSink := &failingAnchorSink{failCount: 1}
	sm := NewSyncManager(g, failSink, time.Millisecond)

	// First flush should fail and re-queue
	err := sm.Flush(context.Background())
	if err == nil {
		t.Fatal("should report anchor failure")
	}
	if g.QueueSize() != 1 {
		t.Fatalf("failed decisions should be re-queued, got queue size %d", g.QueueSize())
	}

	// Second flush should succeed
	err = sm.Flush(context.Background())
	if err != nil {
		t.Fatalf("second flush should succeed: %v", err)
	}
}

func TestDeep_SyncManagerFlushEmpty(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	sm := NewSyncManager(g, NewMemoryAnchorSink(), time.Millisecond)
	if err := sm.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDeep_ConcurrentEvaluateAndFlush(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	sink := NewMemoryAnchorSink()
	sm := NewSyncManager(g, sink, time.Millisecond)

	var wg sync.WaitGroup
	// Writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				g.Evaluate("u", "read")
			}
		}()
	}
	// Flushers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				sm.Flush(context.Background())
			}
		}()
	}
	wg.Wait()

	// Final flush
	sm.Flush(context.Background())
	if g.DecisionCount() != 500 {
		t.Fatalf("expected 500 decisions, got %d", g.DecisionCount())
	}
}

func TestDeep_GuardianCustomClock(t *testing.T) {
	ts := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	g := NewEdgeGuardian(baseConfig())
	g.WithClock(func() time.Time { return ts })
	d := g.Evaluate("u", "read")
	if !d.Timestamp.Equal(ts) {
		t.Fatalf("timestamp=%v, want %v", d.Timestamp, ts)
	}
}

func TestDeep_GuardianDefaultVerdictFallback(t *testing.T) {
	cfg := EdgeConfig{DeviceID: "d", MaxQueueSize: 10}
	g := NewEdgeGuardian(cfg)
	d := g.Evaluate("u", "anything")
	if d.Verdict != "DENY" {
		t.Fatal("empty DefaultVerdict should default to DENY")
	}
}

func TestDeep_MemoryAnchorSinkStoresDecisions(t *testing.T) {
	sink := NewMemoryAnchorSink()
	decisions := []EdgeDecision{{DecisionID: "d1"}, {DecisionID: "d2"}}
	ids, err := sink.Anchor(context.Background(), decisions)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 IDs, got %d", len(ids))
	}
	if len(sink.Anchored()) != 2 {
		t.Fatal("sink should store 2 anchored decisions")
	}
}

func TestDeep_UpdateRulesReplaces(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	d := g.Evaluate("u", "read")
	if d.Verdict != "ALLOW" {
		t.Fatal("read should be ALLOW before update")
	}
	g.UpdateRules([]PolicyRule{{Action: "read", Verdict: "DENY"}})
	d = g.Evaluate("u", "read")
	if d.Verdict != "DENY" {
		t.Fatal("read should be DENY after update")
	}
}

func TestDeep_GuardianReasonFromRule(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	d := g.Evaluate("u", "delete")
	if d.Reason != "destructive" {
		t.Fatalf("reason=%q, want destructive", d.Reason)
	}
}

func TestDeep_GuardianReasonFallbackWhenEmpty(t *testing.T) {
	cfg := EdgeConfig{
		DeviceID:    "d",
		PolicyRules: []PolicyRule{{Action: "x", Verdict: "ALLOW"}},
	}
	g := NewEdgeGuardian(cfg)
	d := g.Evaluate("u", "x")
	if d.Reason == "" {
		t.Fatal("reason should have a fallback")
	}
}

func TestDeep_DecisionCountZeroInitially(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	if g.DecisionCount() != 0 {
		t.Fatal("initial decision count should be 0")
	}
}

func TestDeep_QueueSizeMatchesEvaluations(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	for i := 0; i < 7; i++ {
		g.Evaluate("u", "read")
	}
	if g.QueueSize() != 7 {
		t.Fatalf("queue size should be 7, got %d", g.QueueSize())
	}
}

func TestDeep_FlushThenQueueAgain(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	g.Evaluate("u", "read")
	g.FlushQueue()
	g.Evaluate("u", "write")
	if g.QueueSize() != 1 {
		t.Fatalf("expected 1 queued after reflush, got %d", g.QueueSize())
	}
}

func TestDeep_DeviceIDInDecision(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	d := g.Evaluate("u", "read")
	if d.DeviceID != "dev-1" {
		t.Fatalf("device ID=%q, want dev-1", d.DeviceID)
	}
}

func TestDeep_PrincipalRecorded(t *testing.T) {
	g := NewEdgeGuardian(baseConfig())
	d := g.Evaluate("admin-user", "read")
	if d.Principal != "admin-user" {
		t.Fatalf("principal=%q, want admin-user", d.Principal)
	}
}

// failingAnchorSink fails a configurable number of times then succeeds.
type failingAnchorSink struct {
	mu        sync.Mutex
	calls     int
	failCount int
}

func (f *failingAnchorSink) Anchor(_ context.Context, decisions []EdgeDecision) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failCount {
		return nil, fmt.Errorf("anchor failed (call %d)", f.calls)
	}
	ids := make([]string, len(decisions))
	for i := range decisions {
		ids[i] = fmt.Sprintf("anchor-%d", i)
	}
	return ids, nil
}
