package edge

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestEdgeGuardian_DefaultDeny(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID: "device-1",
	})

	decision := g.Evaluate("agent-1", "UNKNOWN_ACTION")
	if decision.Verdict != "DENY" {
		t.Errorf("expected DENY for unknown action, got %s", decision.Verdict)
	}
}

func TestEdgeGuardian_RuleMatch(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID: "device-1",
		PolicyRules: []PolicyRule{
			{Action: "SEND_EMAIL", Verdict: "ALLOW", Reason: "email permitted"},
			{Action: "INFRA_DESTROY", Verdict: "DENY", Reason: "destructive blocked"},
		},
	})

	allow := g.Evaluate("agent-1", "SEND_EMAIL")
	if allow.Verdict != "ALLOW" {
		t.Errorf("expected ALLOW for SEND_EMAIL, got %s", allow.Verdict)
	}
	if allow.Reason != "email permitted" {
		t.Errorf("expected reason 'email permitted', got %s", allow.Reason)
	}

	deny := g.Evaluate("agent-1", "INFRA_DESTROY")
	if deny.Verdict != "DENY" {
		t.Errorf("expected DENY for INFRA_DESTROY, got %s", deny.Verdict)
	}
}

func TestEdgeGuardian_ContentHash(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "device-2"})

	d := g.Evaluate("agent-1", "TEST")
	if d.ContentHash == "" {
		t.Error("content hash should be non-empty")
	}
	if len(d.ContentHash) != 71 { // "sha256:" + 64 hex chars
		t.Errorf("unexpected content hash length: %d", len(d.ContentHash))
	}
}

func TestEdgeGuardian_DecisionID(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-3"})

	d1 := g.Evaluate("agent-1", "A")
	d2 := g.Evaluate("agent-1", "B")

	if d1.DecisionID == d2.DecisionID {
		t.Error("decision IDs should be unique")
	}
}

func TestEdgeGuardian_QueueAndFlush(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-4"})

	g.Evaluate("agent-1", "A")
	g.Evaluate("agent-1", "B")
	g.Evaluate("agent-1", "C")

	if g.QueueSize() != 3 {
		t.Errorf("expected queue size 3, got %d", g.QueueSize())
	}

	flushed := g.FlushQueue()
	if len(flushed) != 3 {
		t.Errorf("expected 3 flushed, got %d", len(flushed))
	}

	if g.QueueSize() != 0 {
		t.Errorf("expected empty queue after flush, got %d", g.QueueSize())
	}
}

func TestEdgeGuardian_QueueMaxSize(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID:     "dev-5",
		MaxQueueSize: 3,
	})

	for i := 0; i < 10; i++ {
		g.Evaluate("agent-1", fmt.Sprintf("action-%d", i))
	}

	if g.QueueSize() != 3 {
		t.Errorf("expected queue capped at 3, got %d", g.QueueSize())
	}

	if g.DecisionCount() != 10 {
		t.Errorf("expected 10 total decisions, got %d", g.DecisionCount())
	}
}

func TestEdgeGuardian_UpdateRules(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-6"})

	// Initially DENY (default)
	d := g.Evaluate("agent-1", "SEND_EMAIL")
	if d.Verdict != "DENY" {
		t.Errorf("expected DENY before rule update, got %s", d.Verdict)
	}

	// Update rules
	g.UpdateRules([]PolicyRule{
		{Action: "SEND_EMAIL", Verdict: "ALLOW", Reason: "updated"},
	})

	d = g.Evaluate("agent-1", "SEND_EMAIL")
	if d.Verdict != "ALLOW" {
		t.Errorf("expected ALLOW after rule update, got %s", d.Verdict)
	}
}

func TestEdgeGuardian_Clock(t *testing.T) {
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-7"})
	g.WithClock(func() time.Time { return now })

	d := g.Evaluate("agent-1", "TEST")
	if !d.Timestamp.Equal(now) {
		t.Errorf("expected timestamp %v, got %v", now, d.Timestamp)
	}
}

func TestEdgeGuardian_Concurrency(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID: "dev-8",
		PolicyRules: []PolicyRule{
			{Action: "SAFE", Verdict: "ALLOW"},
		},
	})

	var wg sync.WaitGroup
	wg.Add(100)
	for i := 0; i < 100; i++ {
		go func(idx int) {
			defer wg.Done()
			g.Evaluate(fmt.Sprintf("agent-%d", idx), "SAFE")
		}(i)
	}
	wg.Wait()

	if g.DecisionCount() != 100 {
		t.Errorf("expected 100 decisions, got %d", g.DecisionCount())
	}
}

func TestSyncManager_FlushToSink(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-9"})
	sink := NewMemoryAnchorSink()

	g.Evaluate("agent-1", "A")
	g.Evaluate("agent-1", "B")

	sm := NewSyncManager(g, sink, time.Hour) // long interval, we flush manually
	if err := sm.Flush(context.Background()); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	if len(sink.Anchored()) != 2 {
		t.Errorf("expected 2 anchored decisions, got %d", len(sink.Anchored()))
	}

	if g.QueueSize() != 0 {
		t.Errorf("expected empty queue after sync, got %d", g.QueueSize())
	}
}

func TestSyncManager_EmptyFlush(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-10"})
	sink := NewMemoryAnchorSink()

	sm := NewSyncManager(g, sink, time.Hour)
	if err := sm.Flush(context.Background()); err != nil {
		t.Fatalf("empty flush should not error: %v", err)
	}

	if len(sink.Anchored()) != 0 {
		t.Errorf("expected 0 anchored, got %d", len(sink.Anchored()))
	}
}
