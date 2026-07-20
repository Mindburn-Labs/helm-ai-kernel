package metrics

import (
	"strings"
	"testing"
	"time"
)

// HELM-301: arbitrary caller-supplied tool names must not grow the label
// vocabulary without bound, and label-breaking characters are neutralized.
func TestToolLabelCardinalityBounded(t *testing.T) {
	m := NewGovernanceMetrics()
	for i := 0; i < maxToolLabelValues*3; i++ {
		m.RecordDecision(true, "tool-"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+time.Now().Format("150405.000000000"), "", "agent-1", 10)
	}
	snap := m.Snapshot()
	if len(snap.ToolCounts) > maxToolLabelValues+1 { // +1 for the overflow bucket
		t.Fatalf("tool label vocabulary unbounded: %d distinct values", len(snap.ToolCounts))
	}
	if snap.ToolCounts[toolLabelOverflow] == 0 {
		t.Fatal("overflow bucket must absorb excess tool names")
	}
}

func TestToolLabelSanitized(t *testing.T) {
	m := NewGovernanceMetrics()
	m.RecordDecision(true, "evil\"tool\\\nname", "", "agent-1", 10)
	snap := m.Snapshot()
	for tool := range snap.ToolCounts {
		if strings.ContainsAny(tool, "\"\\\n") {
			t.Fatalf("unsanitized tool label reached the vocabulary: %q", tool)
		}
	}
	if _, ok := snap.ToolCounts[`evil_tool__name`]; !ok {
		t.Fatalf("expected sanitized bucket, got %v", snap.ToolCounts)
	}
}

// HELM-302: the active-agent map must not accumulate every id ever seen.
func TestActiveAgentsEvicted(t *testing.T) {
	m := NewGovernanceMetrics()
	// Seed >1024 stale agents.
	stale := time.Now().Add(-time.Hour)
	m.mu.Lock()
	for i := 0; i < 1500; i++ {
		m.activeAgents["stale-"+strings.Repeat("a", i%5)+time.Duration(i).String()] = stale
	}
	m.mu.Unlock()

	m.RecordDecision(true, "tool", "", "fresh-agent", 10)

	m.mu.RLock()
	n := len(m.activeAgents)
	m.mu.RUnlock()
	if n > 1100 {
		t.Fatalf("stale agents not evicted: %d entries remain", n)
	}
}
