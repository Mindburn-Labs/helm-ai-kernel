package edge

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFinal_NewEdgeGuardianDefaults(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	if g == nil {
		t.Fatal("nil guardian")
	}
}

func TestFinal_DefaultVerdictDeny(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	d := g.Evaluate("user1", "unknown_action")
	if d.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", d.Verdict)
	}
}

func TestFinal_DefaultVerdictOverride(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1", DefaultVerdict: "ALLOW"})
	d := g.Evaluate("user1", "unknown_action")
	if d.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s", d.Verdict)
	}
}

func TestFinal_RuleMatch(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID:    "d1",
		PolicyRules: []PolicyRule{{Action: "read", Verdict: "ALLOW", Reason: "safe"}},
	})
	d := g.Evaluate("user1", "read")
	if d.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s", d.Verdict)
	}
}

func TestFinal_DecisionIDFormat(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "dev-42"})
	d := g.Evaluate("user1", "act")
	if !strings.HasPrefix(d.DecisionID, "edge-dev-42-") {
		t.Fatalf("unexpected ID: %s", d.DecisionID)
	}
}

func TestFinal_ContentHashPrefix(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	d := g.Evaluate("user1", "act")
	if !strings.HasPrefix(d.ContentHash, "sha256:") {
		t.Fatal("missing sha256 prefix")
	}
}

func TestFinal_ContentHashDeterministic(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	g.WithClock(func() time.Time { return fixed })
	d1 := g.Evaluate("user1", "act")
	g2 := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	g2.WithClock(func() time.Time { return fixed })
	d2 := g2.Evaluate("user1", "act")
	if d1.ContentHash != d2.ContentHash {
		t.Fatal("hashes should match")
	}
}

func TestFinal_DecisionCountIncrement(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	g.Evaluate("u", "a")
	g.Evaluate("u", "b")
	if g.DecisionCount() != 2 {
		t.Fatalf("expected 2, got %d", g.DecisionCount())
	}
}

func TestFinal_QueueSizeGrows(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	g.Evaluate("u", "a")
	if g.QueueSize() != 1 {
		t.Fatal("queue should have 1")
	}
}

func TestFinal_QueueMaxSize(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1", MaxQueueSize: 2})
	g.Evaluate("u", "a")
	g.Evaluate("u", "b")
	d := g.Evaluate("u", "c")
	if !d.QueueFull {
		t.Fatal("queue should be full")
	}
	if g.QueueSize() != 2 {
		t.Fatal("queue should cap at 2")
	}
}

func TestFinal_FlushQueueReturnsAll(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	g.Evaluate("u", "a")
	g.Evaluate("u", "b")
	flushed := g.FlushQueue()
	if len(flushed) != 2 {
		t.Fatalf("expected 2, got %d", len(flushed))
	}
	if g.QueueSize() != 0 {
		t.Fatal("queue should be empty after flush")
	}
}

func TestFinal_FlushQueueEmpty(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	flushed := g.FlushQueue()
	if len(flushed) != 0 {
		t.Fatal("should be empty")
	}
}

func TestFinal_UpdateRules(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	g.UpdateRules([]PolicyRule{{Action: "write", Verdict: "ALLOW"}})
	d := g.Evaluate("u", "write")
	if d.Verdict != "ALLOW" {
		t.Fatal("updated rule not applied")
	}
}

func TestFinal_UpdateRulesClearsOld(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID:    "d1",
		PolicyRules: []PolicyRule{{Action: "read", Verdict: "ALLOW"}},
	})
	g.UpdateRules([]PolicyRule{{Action: "write", Verdict: "ALLOW"}})
	d := g.Evaluate("u", "read")
	if d.Verdict != "DENY" {
		t.Fatal("old rule should be cleared")
	}
}

func TestFinal_WithClock(t *testing.T) {
	fixed := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	g.WithClock(func() time.Time { return fixed })
	d := g.Evaluate("u", "a")
	if !d.Timestamp.Equal(fixed) {
		t.Fatal("clock not injected")
	}
}

func TestFinal_EdgeDecisionJSONRoundTrip(t *testing.T) {
	d := EdgeDecision{DecisionID: "d1", Verdict: "ALLOW", DeviceID: "dev"}
	data, _ := json.Marshal(d)
	var got EdgeDecision
	json.Unmarshal(data, &got)
	if got.DecisionID != "d1" || got.Verdict != "ALLOW" {
		t.Fatal("round-trip")
	}
}

func TestFinal_EdgeConfigJSONRoundTrip(t *testing.T) {
	cfg := EdgeConfig{DeviceID: "d1", DefaultVerdict: "DENY", MaxQueueSize: 100}
	data, _ := json.Marshal(cfg)
	var got EdgeConfig
	json.Unmarshal(data, &got)
	if got.DeviceID != "d1" || got.MaxQueueSize != 100 {
		t.Fatal("config round-trip")
	}
}

func TestFinal_PolicyRuleJSONRoundTrip(t *testing.T) {
	r := PolicyRule{Action: "deploy", Verdict: "DENY", Reason: "restricted"}
	data, _ := json.Marshal(r)
	var got PolicyRule
	json.Unmarshal(data, &got)
	if got.Action != "deploy" || got.Reason != "restricted" {
		t.Fatal("rule round-trip")
	}
}

func TestFinal_DefaultMaxQueueSize(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	if g.config.MaxQueueSize != 1000 {
		t.Fatalf("expected 1000, got %d", g.config.MaxQueueSize)
	}
}

func TestFinal_MemoryAnchorSinkCreate(t *testing.T) {
	sink := NewMemoryAnchorSink()
	if sink == nil {
		t.Fatal("nil sink")
	}
}

func TestFinal_MemoryAnchorSinkAnchor(t *testing.T) {
	sink := NewMemoryAnchorSink()
	decisions := []EdgeDecision{{DecisionID: "d1"}, {DecisionID: "d2"}}
	ids, err := sink.Anchor(nil, decisions)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatal("expected 2 anchor IDs")
	}
}

func TestFinal_MemoryAnchorSinkAnchored(t *testing.T) {
	sink := NewMemoryAnchorSink()
	sink.Anchor(nil, []EdgeDecision{{DecisionID: "d1"}})
	if len(sink.Anchored()) != 1 {
		t.Fatal("expected 1 anchored")
	}
}

func TestFinal_AnchorIDPrefix(t *testing.T) {
	sink := NewMemoryAnchorSink()
	ids, _ := sink.Anchor(nil, []EdgeDecision{{DecisionID: "d1"}})
	if !strings.HasPrefix(ids[0], "anchor-") {
		t.Fatalf("unexpected prefix: %s", ids[0])
	}
}

func TestFinal_SyncManagerCreate(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	sink := NewMemoryAnchorSink()
	sm := NewSyncManager(g, sink, time.Second)
	if sm == nil {
		t.Fatal("nil sync manager")
	}
}

func TestFinal_SyncManagerFlush(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	g.Evaluate("u", "a")
	sink := NewMemoryAnchorSink()
	sm := NewSyncManager(g, sink, time.Second)
	err := sm.Flush(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sink.Anchored()) != 1 {
		t.Fatal("should have 1 anchored")
	}
}

func TestFinal_SyncManagerFlushEmpty(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	sink := NewMemoryAnchorSink()
	sm := NewSyncManager(g, sink, time.Second)
	err := sm.Flush(nil)
	if err != nil {
		t.Fatal("empty flush should not error")
	}
}

func TestFinal_RuleReasonDefault(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{
		DeviceID:    "d1",
		PolicyRules: []PolicyRule{{Action: "test", Verdict: "ALLOW"}},
	})
	d := g.Evaluate("u", "test")
	if d.Reason == "" {
		t.Fatal("reason should be set even without explicit reason")
	}
}

func TestFinal_DefaultPolicyReason(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	d := g.Evaluate("u", "unknown")
	if d.Reason != "default policy" {
		t.Fatalf("expected 'default policy', got %q", d.Reason)
	}
}

func TestFinal_AnchoredFlagFalseByDefault(t *testing.T) {
	g := NewEdgeGuardian(EdgeConfig{DeviceID: "d1"})
	d := g.Evaluate("u", "a")
	if d.Anchored {
		t.Fatal("should not be anchored yet")
	}
}
