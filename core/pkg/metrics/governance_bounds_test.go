package metrics

import (
	"strconv"
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
	start := time.Date(2026, time.August, 13, 0, 0, 0, 0, time.UTC)
	now := start
	m.now = func() time.Time { return now }

	const (
		agentCount = 100_000
		step       = 100 * time.Millisecond
	)
	for i := 0; i < agentCount; i++ {
		now = start.Add(time.Duration(i) * step)
		m.RecordDecision(true, "tool", "", "agent-"+strconv.Itoa(i), 10)
	}

	m.mu.RLock()
	retained := len(m.activeAgents)
	m.mu.RUnlock()
	maxRetained := int((activeAgentRetention+activeAgentSweepInterval)/step) + 1
	if retained > maxRetained {
		t.Fatalf("agent map did not converge: retained %d of %d, want <= %d", retained, agentCount, maxRetained)
	}

	if got, want := m.Snapshot().ActiveAgents, int(activeAgentWindow/step); got != want {
		t.Fatalf("active-agent window mismatch: got %d, want %d", got, want)
	}
	now = now.Add(activeAgentWindow + time.Nanosecond)
	if got := m.Snapshot().ActiveAgents; got != 0 {
		t.Fatalf("stale agents remained active after window: got %d, want 0", got)
	}
}
