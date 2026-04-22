package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecordDecision(t *testing.T) {
	m := NewGovernanceMetrics()
	m.RecordDecision(true, "read_file", "", "agent-001", 1500)
	m.RecordDecision(false, "write_file", "PDP_DENY", "agent-002", 2500)

	snap := m.Snapshot()
	if snap.Decisions != 2 {
		t.Errorf("expected 2 decisions, got %d", snap.Decisions)
	}
	if snap.Allows != 1 {
		t.Errorf("expected 1 allow, got %d", snap.Allows)
	}
	if snap.Denials != 1 {
		t.Errorf("expected 1 denial, got %d", snap.Denials)
	}
	if snap.ToolCounts["read_file"] != 1 {
		t.Error("read_file count incorrect")
	}
	if snap.ToolCounts["write_file"] != 1 {
		t.Error("write_file count incorrect")
	}
	if snap.ReasonCounts["PDP_DENY"] != 1 {
		t.Error("PDP_DENY reason count incorrect")
	}
}

func TestDenyRate(t *testing.T) {
	m := NewGovernanceMetrics()
	for i := 0; i < 8; i++ {
		m.RecordDecision(true, "read_file", "", "a", 1000)
	}
	for i := 0; i < 2; i++ {
		m.RecordDecision(false, "write_file", "DENY", "a", 1000)
	}

	snap := m.Snapshot()
	if snap.DenyRate < 19.0 || snap.DenyRate > 21.0 {
		t.Errorf("expected ~20%% deny rate, got %.1f%%", snap.DenyRate)
	}
}

func TestActiveAgents(t *testing.T) {
	m := NewGovernanceMetrics()
	m.RecordDecision(true, "t", "", "agent-001", 1000)
	m.RecordDecision(true, "t", "", "agent-002", 1000)
	m.RecordDecision(true, "t", "", "agent-001", 1000) // duplicate

	snap := m.Snapshot()
	if snap.ActiveAgents != 2 {
		t.Errorf("expected 2 active agents, got %d", snap.ActiveAgents)
	}
}

func TestJSONHandler(t *testing.T) {
	m := NewGovernanceMetrics()
	m.RecordDecision(true, "read_file", "", "a", 1000)

	req := httptest.NewRequest(http.MethodGet, "/metrics/json", nil)
	w := httptest.NewRecorder()
	m.Handler()(w, req)

	if w.Code != http.StatusOK {
		t.Error("expected 200")
	}

	var snap MetricsSnapshot
	json.NewDecoder(w.Body).Decode(&snap)
	if snap.Decisions != 1 {
		t.Error("JSON metrics mismatch")
	}
}

func TestPrometheusHandler(t *testing.T) {
	m := NewGovernanceMetrics()
	m.RecordDecision(true, "read_file", "", "a", 1500)
	m.RecordDecision(false, "write_file", "DENY", "b", 2500)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler()(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "helm_decisions_total 2") {
		t.Error("expected helm_decisions_total 2")
	}
	if !strings.Contains(body, "helm_allows_total 1") {
		t.Error("expected helm_allows_total 1")
	}
	if !strings.Contains(body, "helm_denials_total 1") {
		t.Error("expected helm_denials_total 1")
	}
	if !strings.Contains(body, `helm_tool_decisions{tool="read_file"}`) {
		t.Error("expected tool counters")
	}
	if !strings.Contains(body, `helm_denial_reasons{reason="DENY"}`) {
		t.Error("expected reason counters")
	}
}

func TestBudget(t *testing.T) {
	m := NewGovernanceMetrics()
	m.SetBudget(5000, 10000)

	snap := m.Snapshot()
	if snap.BudgetUsed < 49.0 || snap.BudgetUsed > 51.0 {
		t.Errorf("expected ~50%% budget usage, got %.1f%%", snap.BudgetUsed)
	}
}
