package edge

import (
	"context"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedTime }

func defaultConfig() EdgeConfig {
	return EdgeConfig{
		DeviceID:       "dev-1",
		DefaultVerdict: "DENY",
		MaxQueueSize:   100,
		PolicyRules: []PolicyRule{
			{Action: "read", Verdict: "ALLOW", Reason: "permitted"},
			{Action: "delete", Verdict: "DENY", Reason: "blocked"},
		},
	}
}

func TestEdgeGuardianEvaluateAllowRule(t *testing.T) {
	g := NewEdgeGuardian(defaultConfig())
	g.WithClock(fixedClock)
	d := g.Evaluate("user-1", "read")
	if d.Verdict != "ALLOW" || d.Reason != "permitted" {
		t.Fatalf("expected ALLOW/permitted, got %s/%s", d.Verdict, d.Reason)
	}
}

func TestEdgeGuardianEvaluateDenyRule(t *testing.T) {
	g := NewEdgeGuardian(defaultConfig())
	d := g.Evaluate("user-1", "delete")
	if d.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", d.Verdict)
	}
}

func TestEdgeGuardianDefaultVerdictDeny(t *testing.T) {
	g := NewEdgeGuardian(defaultConfig())
	d := g.Evaluate("user-1", "unknown-action")
	if d.Verdict != "DENY" || d.Reason != "default policy" {
		t.Fatalf("expected DENY/default, got %s/%s", d.Verdict, d.Reason)
	}
}

func TestEdgeGuardianDefaultVerdictAllow(t *testing.T) {
	cfg := EdgeConfig{DeviceID: "d1", DefaultVerdict: "ALLOW"}
	g := NewEdgeGuardian(cfg)
	d := g.Evaluate("user-1", "anything")
	if d.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW default, got %s", d.Verdict)
	}
}

func TestEdgeGuardianDecisionIDFormat(t *testing.T) {
	g := NewEdgeGuardian(defaultConfig())
	d := g.Evaluate("u", "read")
	if !strings.HasPrefix(d.DecisionID, "edge-dev-1-") {
		t.Fatalf("expected edge-dev-1- prefix, got %s", d.DecisionID)
	}
}

func TestEdgeGuardianContentHashPopulated(t *testing.T) {
	g := NewEdgeGuardian(defaultConfig())
	d := g.Evaluate("u", "read")
	if !strings.HasPrefix(d.ContentHash, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", d.ContentHash)
	}
}

func TestEdgeGuardianQueueAccumulates(t *testing.T) {
	g := NewEdgeGuardian(defaultConfig())
	g.Evaluate("u", "read")
	g.Evaluate("u", "read")
	if g.QueueSize() != 2 {
		t.Fatalf("expected queue size 2, got %d", g.QueueSize())
	}
}

func TestEdgeGuardianFlushClearsQueue(t *testing.T) {
	g := NewEdgeGuardian(defaultConfig())
	g.Evaluate("u", "read")
	flushed := g.FlushQueue()
	if len(flushed) != 1 || g.QueueSize() != 0 {
		t.Fatalf("flush: got %d items, queue=%d", len(flushed), g.QueueSize())
	}
}

func TestEdgeGuardianQueueFullFlag(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxQueueSize = 1
	g := NewEdgeGuardian(cfg)
	g.Evaluate("u", "read") // fills queue
	d := g.Evaluate("u", "read")
	if !d.QueueFull {
		t.Fatal("expected QueueFull=true when at capacity")
	}
}

func TestEdgeGuardianDecisionCount(t *testing.T) {
	g := NewEdgeGuardian(defaultConfig())
	g.Evaluate("u", "read")
	g.Evaluate("u", "delete")
	if g.DecisionCount() != 2 {
		t.Fatalf("expected 2 decisions, got %d", g.DecisionCount())
	}
}

func TestEdgeGuardianUpdateRules(t *testing.T) {
	g := NewEdgeGuardian(defaultConfig())
	g.UpdateRules([]PolicyRule{{Action: "write", Verdict: "ALLOW"}})
	d := g.Evaluate("u", "write")
	if d.Verdict != "ALLOW" {
		t.Fatalf("updated rule should allow write, got %s", d.Verdict)
	}
	d2 := g.Evaluate("u", "read") // no longer has read rule
	if d2.Verdict != "DENY" {
		t.Fatalf("read should fall to default DENY after update, got %s", d2.Verdict)
	}
}

func TestMemoryAnchorSinkAnchors(t *testing.T) {
	sink := NewMemoryAnchorSink()
	decisions := []EdgeDecision{{DecisionID: "d1"}, {DecisionID: "d2"}}
	ids, err := sink.Anchor(context.Background(), decisions)
	if err != nil || len(ids) != 2 {
		t.Fatalf("anchor: err=%v ids=%d", err, len(ids))
	}
	if len(sink.Anchored()) != 2 {
		t.Fatalf("expected 2 anchored, got %d", len(sink.Anchored()))
	}
}

func TestSyncManagerFlush(t *testing.T) {
	g := NewEdgeGuardian(defaultConfig())
	sink := NewMemoryAnchorSink()
	sm := NewSyncManager(g, sink, time.Second)
	g.Evaluate("u", "read")
	if err := sm.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if g.QueueSize() != 0 {
		t.Fatal("queue should be empty after flush")
	}
	if len(sink.Anchored()) != 1 {
		t.Fatalf("expected 1 anchored, got %d", len(sink.Anchored()))
	}
}

func TestSyncManagerFlushEmpty(t *testing.T) {
	g := NewEdgeGuardian(defaultConfig())
	sink := NewMemoryAnchorSink()
	sm := NewSyncManager(g, sink, time.Second)
	if err := sm.Flush(context.Background()); err != nil {
		t.Fatalf("flush empty should not error: %v", err)
	}
}

func TestEdgeGuardianDefaultVerdictFallsToDefaults(t *testing.T) {
	cfg := EdgeConfig{DeviceID: "d"} // no DefaultVerdict, no MaxQueueSize
	g := NewEdgeGuardian(cfg)
	d := g.Evaluate("u", "x")
	if d.Verdict != "DENY" {
		t.Fatalf("empty config should default to DENY, got %s", d.Verdict)
	}
}
