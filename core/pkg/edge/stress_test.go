package edge

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

var edgeClock = func() time.Time { return time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC) }

// --- Guardian 5000 Decisions ---

func TestStress_Guardian_5000Decisions(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID:       "dev-5k",
		DefaultVerdict: "DENY",
		PolicyRules:    []PolicyRule{{Action: "read", Verdict: "ALLOW"}},
		MaxQueueSize:   6000,
	})
	g.WithClock(edgeClock)
	for i := 0; i < 5000; i++ {
		d := g.Evaluate("user", "read")
		if d.Verdict != "ALLOW" {
			t.Fatalf("decision %d: expected ALLOW, got %s", i, d.Verdict)
		}
	}
	if g.DecisionCount() != 5000 {
		t.Fatalf("expected 5000 decisions, got %d", g.DecisionCount())
	}
}

func TestStress_Guardian_DefaultDeny(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-deny", DefaultVerdict: "DENY"})
	d := g.Evaluate("user", "unknown_action")
	if d.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", d.Verdict)
	}
}

func TestStress_Guardian_DefaultAllow(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-allow", DefaultVerdict: "ALLOW"})
	d := g.Evaluate("user", "anything")
	if d.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s", d.Verdict)
	}
}

func TestStress_Guardian_ContentHashSet(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-hash"})
	d := g.Evaluate("user", "action")
	if d.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestStress_Guardian_DecisionIDs_Unique(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-unique", MaxQueueSize: 200})
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		d := g.Evaluate("u", "a")
		if seen[d.DecisionID] {
			t.Fatalf("duplicate decision ID: %s", d.DecisionID)
		}
		seen[d.DecisionID] = true
	}
}

func TestStress_Guardian_MultipleRules(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID: "dev-multi",
		PolicyRules: []PolicyRule{
			{Action: "read", Verdict: "ALLOW"},
			{Action: "write", Verdict: "DENY", Reason: "read-only"},
			{Action: "exec", Verdict: "DENY", Reason: "no-exec"},
		},
	})
	if g.Evaluate("u", "read").Verdict != "ALLOW" {
		t.Fatal("read should ALLOW")
	}
	if g.Evaluate("u", "write").Verdict != "DENY" {
		t.Fatal("write should DENY")
	}
	if g.Evaluate("u", "exec").Verdict != "DENY" {
		t.Fatal("exec should DENY")
	}
}

// --- Queue Stress ---

func TestStress_Guardian_QueueAtExactCapacity(t *testing.T) {
	cap := 10
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-cap", MaxQueueSize: cap})
	for i := 0; i < cap; i++ {
		d := g.Evaluate("u", "a")
		if d.QueueFull {
			t.Fatalf("queue full at %d, expected capacity %d", i, cap)
		}
	}
	if g.QueueSize() != cap {
		t.Fatalf("expected queue size %d, got %d", cap, g.QueueSize())
	}
}

func TestStress_Guardian_QueueOverflow(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-overflow", MaxQueueSize: 5})
	for i := 0; i < 5; i++ {
		g.Evaluate("u", "a")
	}
	d := g.Evaluate("u", "a")
	if !d.QueueFull {
		t.Fatal("expected QueueFull=true when over capacity")
	}
}

func TestStress_Guardian_FlushClearsQueue(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-flush", MaxQueueSize: 100})
	for i := 0; i < 50; i++ {
		g.Evaluate("u", "a")
	}
	flushed := g.FlushQueue()
	if len(flushed) != 50 {
		t.Fatalf("expected 50 flushed, got %d", len(flushed))
	}
	if g.QueueSize() != 0 {
		t.Fatalf("expected queue empty after flush, got %d", g.QueueSize())
	}
}

func TestStress_Guardian_FlushEmpty(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-empty"})
	flushed := g.FlushQueue()
	if len(flushed) != 0 {
		t.Fatalf("expected 0 flushed, got %d", len(flushed))
	}
}

// --- UpdateRules Stress ---

func TestStress_Guardian_UpdateRules100Times(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-update"})
	for i := 0; i < 100; i++ {
		rules := []PolicyRule{
			{Action: fmt.Sprintf("action-%d", i), Verdict: "ALLOW"},
		}
		g.UpdateRules(rules)
		d := g.Evaluate("u", fmt.Sprintf("action-%d", i))
		if d.Verdict != "ALLOW" {
			t.Fatalf("update %d: expected ALLOW after rule update", i)
		}
	}
}

func TestStress_Guardian_UpdateRulesOverwrite(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID:    "dev-overwrite",
		PolicyRules: []PolicyRule{{Action: "a", Verdict: "ALLOW"}},
	})
	if g.Evaluate("u", "a").Verdict != "ALLOW" {
		t.Fatal("expected ALLOW before update")
	}
	g.UpdateRules([]PolicyRule{{Action: "a", Verdict: "DENY"}})
	if g.Evaluate("u", "a").Verdict != "DENY" {
		t.Fatal("expected DENY after update")
	}
}

func TestStress_Guardian_UpdateRulesClearsPrevious(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID:       "dev-clear",
		DefaultVerdict: "DENY",
		PolicyRules:    []PolicyRule{{Action: "old", Verdict: "ALLOW"}},
	})
	g.UpdateRules([]PolicyRule{{Action: "new", Verdict: "ALLOW"}})
	if g.Evaluate("u", "old").Verdict != "DENY" {
		t.Fatal("old rule should no longer be active")
	}
}

// --- Sync Stress ---

func TestStress_Sync_FailingSucceedingSinkAlternating(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-alt", MaxQueueSize: 100})
	g.WithClock(edgeClock)
	callCount := 0
	sink := &alternatingSink{failEvery: 2, calls: &callCount}
	sm := NewSyncManager(g, sink, time.Hour)
	g.Evaluate("u", "a")
	// First flush succeeds
	if err := sm.Flush(context.Background()); err != nil {
		t.Fatalf("first flush should succeed: %v", err)
	}
	// Second flush: add item, fail
	g.Evaluate("u", "a")
	callCount = 1
	if err := sm.Flush(context.Background()); err == nil {
		t.Fatal("second flush should fail")
	}
	// Items re-queued, third flush succeeds
	callCount = 2
	if err := sm.Flush(context.Background()); err != nil {
		t.Fatalf("third flush should succeed: %v", err)
	}
}

type alternatingSink struct {
	failEvery int
	calls     *int
}

func (s *alternatingSink) Anchor(_ context.Context, decisions []EdgeDecision) ([]string, error) {
	*s.calls++
	if *s.calls%s.failEvery == 0 {
		return nil, fmt.Errorf("simulated failure")
	}
	ids := make([]string, len(decisions))
	for i := range decisions {
		ids[i] = fmt.Sprintf("anch-%d", i)
	}
	return ids, nil
}

func TestStress_Sync_FlushNoItems(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-noitems"})
	sink := NewMemoryAnchorSink()
	sm := NewSyncManager(g, sink, time.Hour)
	if err := sm.Flush(context.Background()); err != nil {
		t.Fatalf("flush with no items should not error: %v", err)
	}
}

func TestStress_Sync_MemoryAnchorSink(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-mem", MaxQueueSize: 100})
	for i := 0; i < 20; i++ {
		g.Evaluate("u", "a")
	}
	sink := NewMemoryAnchorSink()
	sm := NewSyncManager(g, sink, time.Hour)
	if err := sm.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.Anchored()) != 20 {
		t.Fatalf("expected 20 anchored, got %d", len(sink.Anchored()))
	}
}

// --- Concurrent Evaluate+Flush ---

func TestStress_Concurrent_EvaluateAndFlush_50Goroutines(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-conc", MaxQueueSize: 10000})
	sink := NewMemoryAnchorSink()
	sm := NewSyncManager(g, sink, time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				g.Evaluate(fmt.Sprintf("user-%d", id), "action")
			}
		}(i)
	}
	// Concurrent flushes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sm.Flush(context.Background())
		}()
	}
	wg.Wait()
	if g.DecisionCount() != 5000 {
		t.Fatalf("expected 5000 decisions, got %d", g.DecisionCount())
	}
}

func TestStress_Concurrent_UpdateAndEvaluate(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-race", MaxQueueSize: 10000})
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			g.UpdateRules([]PolicyRule{{Action: fmt.Sprintf("a-%d", id), Verdict: "ALLOW"}})
		}(i)
	}
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				g.Evaluate("u", "a")
			}
		}()
	}
	wg.Wait()
}

func TestStress_Guardian_ReasonFromRule(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID:    "dev-reason",
		PolicyRules: []PolicyRule{{Action: "read", Verdict: "ALLOW", Reason: "permitted"}},
	})
	d := g.Evaluate("u", "read")
	if d.Reason != "permitted" {
		t.Fatalf("expected reason 'permitted', got %q", d.Reason)
	}
}

func TestStress_Guardian_ReasonDefault(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID:    "dev-def-reason",
		PolicyRules: []PolicyRule{{Action: "read", Verdict: "ALLOW"}},
	})
	d := g.Evaluate("u", "read")
	if d.Reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestStress_Guardian_DefaultVerdictFallback(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-fallback"})
	d := g.Evaluate("u", "nonexistent")
	if d.Verdict != "DENY" {
		t.Fatalf("expected DENY default, got %s", d.Verdict)
	}
}

func TestStress_Guardian_DeviceIDInDecision(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "my-device-42"})
	d := g.Evaluate("u", "a")
	if d.DeviceID != "my-device-42" {
		t.Fatalf("expected device ID in decision, got %s", d.DeviceID)
	}
}

func TestStress_Guardian_PrincipalPreserved(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev"})
	d := g.Evaluate("admin@helm.io", "a")
	if d.Principal != "admin@helm.io" {
		t.Fatalf("expected principal preserved, got %s", d.Principal)
	}
}

func TestStress_Guardian_ActionPreserved(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev"})
	d := g.Evaluate("u", "deploy_production")
	if d.Action != "deploy_production" {
		t.Fatalf("expected action preserved, got %s", d.Action)
	}
}

func TestStress_Guardian_SequentialSequence(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-seq"})
	for i := 0; i < 10; i++ {
		g.Evaluate("u", "a")
	}
	if g.DecisionCount() != 10 {
		t.Fatalf("expected 10, got %d", g.DecisionCount())
	}
}

func TestStress_Guardian_EmptyConfig(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{})
	d := g.Evaluate("u", "a")
	if d.Verdict != "DENY" {
		t.Fatalf("empty config should default to DENY, got %s", d.Verdict)
	}
}

func TestStress_Guardian_QueueSizeTracking(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-qs", MaxQueueSize: 100})
	for i := 0; i < 25; i++ {
		g.Evaluate("u", "a")
	}
	if g.QueueSize() != 25 {
		t.Fatalf("expected queue size 25, got %d", g.QueueSize())
	}
}

func TestStress_Guardian_FlushDoesNotResetDecisionCount(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-fdc", MaxQueueSize: 100})
	for i := 0; i < 10; i++ {
		g.Evaluate("u", "a")
	}
	g.FlushQueue()
	if g.DecisionCount() != 10 {
		t.Fatalf("flush should not reset decision count, got %d", g.DecisionCount())
	}
}

func TestStress_Guardian_QueueOverflowStillRecordsDecision(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-ovrec", MaxQueueSize: 1})
	g.Evaluate("u", "a")
	d := g.Evaluate("u", "b")
	if d.QueueFull != true {
		t.Fatal("expected queue full")
	}
	if g.DecisionCount() != 2 {
		t.Fatal("decision should still be counted even when queue full")
	}
}

func TestStress_Guardian_DefaultQueueSize(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-dqs"})
	for i := 0; i < 1000; i++ {
		g.Evaluate("u", "a")
	}
	if g.QueueSize() != 1000 {
		t.Fatalf("default max queue should be 1000, got %d", g.QueueSize())
	}
}

func TestStress_Guardian_MultiFlush(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-mf", MaxQueueSize: 100})
	for i := 0; i < 30; i++ {
		g.Evaluate("u", "a")
	}
	f1 := g.FlushQueue()
	for i := 0; i < 20; i++ {
		g.Evaluate("u", "b")
	}
	f2 := g.FlushQueue()
	if len(f1) != 30 || len(f2) != 20 {
		t.Fatalf("expected 30+20 flushed, got %d+%d", len(f1), len(f2))
	}
}

func TestStress_Guardian_1000DecisionsAllDeny(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-1kd", DefaultVerdict: "DENY", MaxQueueSize: 2000})
	for i := 0; i < 1000; i++ {
		d := g.Evaluate("u", fmt.Sprintf("action-%d", i))
		if d.Verdict != "DENY" {
			t.Fatalf("decision %d: expected DENY", i)
		}
	}
}

func TestStress_Guardian_TimestampSet(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-ts"})
	g.WithClock(edgeClock)
	d := g.Evaluate("u", "a")
	if d.Timestamp != edgeClock() {
		t.Fatal("expected clock-injected timestamp")
	}
}

func TestStress_Guardian_RuleReasonFallback(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID:    "dev-rfb",
		PolicyRules: []PolicyRule{{Action: "x", Verdict: "ALLOW"}},
	})
	d := g.Evaluate("u", "x")
	if d.Reason == "" {
		t.Fatal("expected auto-generated reason for rule without explicit reason")
	}
}

func TestStress_Concurrent_FlushAndEvaluate(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-cfe", MaxQueueSize: 10000})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				g.Evaluate("u", "a")
			}
		}()
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.FlushQueue()
		}()
	}
	wg.Wait()
}

func TestStress_Sync_FailingSinkRequeues(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-fsrq", MaxQueueSize: 100})
	for i := 0; i < 5; i++ {
		g.Evaluate("u", "a")
	}
	failSink := &failingSink{}
	sm := NewSyncManager(g, failSink, time.Hour)
	err := sm.Flush(context.Background())
	if err == nil {
		t.Fatal("expected error from failing sink")
	}
	if g.QueueSize() != 5 {
		t.Fatalf("expected items re-queued, got queue size %d", g.QueueSize())
	}
}

type failingSink struct{}

func (s *failingSink) Anchor(_ context.Context, _ []EdgeDecision) ([]string, error) {
	return nil, fmt.Errorf("always fails")
}

func TestStress_Guardian_NotAnchoredByDefault(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-na"})
	d := g.Evaluate("u", "a")
	if d.Anchored {
		t.Fatal("decisions should not be anchored by default")
	}
}

func TestStress_Guardian_UpdateRulesEmpty(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID:       "dev-ure",
		DefaultVerdict: "DENY",
		PolicyRules:    []PolicyRule{{Action: "a", Verdict: "ALLOW"}},
	})
	g.UpdateRules([]PolicyRule{})
	d := g.Evaluate("u", "a")
	if d.Verdict != "DENY" {
		t.Fatal("expected DENY after clearing all rules")
	}
}

func TestStress_Guardian_QueueSizeZeroAfterFlush(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-qsz", MaxQueueSize: 50})
	for i := 0; i < 50; i++ {
		g.Evaluate("u", "a")
	}
	g.FlushQueue()
	if g.QueueSize() != 0 {
		t.Fatalf("expected 0 after flush, got %d", g.QueueSize())
	}
}

func TestStress_Sync_StopDoesNotPanic(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-stop"})
	sink := NewMemoryAnchorSink()
	sm := NewSyncManager(g, sink, time.Hour)
	sm.Stop()
}
