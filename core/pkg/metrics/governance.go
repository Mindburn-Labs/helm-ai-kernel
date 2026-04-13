// Package metrics provides a Prometheus-compatible metrics endpoint
// for the HELM Dashboard to consume.
//
// Exposes governance metrics over /metrics for real-time dashboard wiring.
package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// GovernanceMetrics tracks governance decision metrics.
type GovernanceMetrics struct {
	mu              sync.RWMutex
	decisions       int64
	allows          int64
	denials         int64
	latencySum      int64 // microseconds
	latencyCount    int64
	latencyP99      int64 // microseconds
	toolCounts      map[string]int64
	reasonCounts    map[string]int64
	activeAgents    map[string]time.Time
	budgetUsed      int64
	budgetCeiling   int64
	chainLength     int64
	latencyBuckets  []int64 // histogram buckets
}

// NewGovernanceMetrics creates a new metrics collector.
func NewGovernanceMetrics() *GovernanceMetrics {
	return &GovernanceMetrics{
		toolCounts:   make(map[string]int64),
		reasonCounts: make(map[string]int64),
		activeAgents: make(map[string]time.Time),
	}
}

// RecordDecision records a governance decision metric.
func (m *GovernanceMetrics) RecordDecision(allowed bool, tool, reasonCode, agentID string, latencyUs int64) {
	atomic.AddInt64(&m.decisions, 1)
	if allowed {
		atomic.AddInt64(&m.allows, 1)
	} else {
		atomic.AddInt64(&m.denials, 1)
	}
	atomic.AddInt64(&m.latencySum, latencyUs)
	atomic.AddInt64(&m.latencyCount, 1)
	atomic.AddInt64(&m.chainLength, 1)

	m.mu.Lock()
	m.toolCounts[tool]++
	if reasonCode != "" {
		m.reasonCounts[reasonCode]++
	}
	m.activeAgents[agentID] = time.Now()
	m.mu.Unlock()
}

// SetBudget updates budget tracking.
func (m *GovernanceMetrics) SetBudget(used, ceiling int64) {
	atomic.StoreInt64(&m.budgetUsed, used)
	atomic.StoreInt64(&m.budgetCeiling, ceiling)
}

// Snapshot returns a point-in-time metrics snapshot.
type MetricsSnapshot struct {
	Decisions    int64            `json:"decisions_total"`
	Allows       int64            `json:"allows_total"`
	Denials      int64            `json:"denials_total"`
	DenyRate     float64          `json:"deny_rate"`
	AvgLatencyMs float64         `json:"avg_latency_ms"`
	P99LatencyMs float64         `json:"p99_latency_ms"`
	ChainLength  int64            `json:"chain_length"`
	ActiveAgents int              `json:"active_agents"`
	BudgetUsed   float64          `json:"budget_used_pct"`
	ToolCounts   map[string]int64 `json:"tool_counts"`
	ReasonCounts map[string]int64 `json:"reason_counts"`
	Timestamp    string           `json:"timestamp"`
}

// Snapshot returns current metrics.
func (m *GovernanceMetrics) Snapshot() MetricsSnapshot {
	dec := atomic.LoadInt64(&m.decisions)
	allows := atomic.LoadInt64(&m.allows)
	denials := atomic.LoadInt64(&m.denials)
	latSum := atomic.LoadInt64(&m.latencySum)
	latCount := atomic.LoadInt64(&m.latencyCount)
	budgetUsed := atomic.LoadInt64(&m.budgetUsed)
	budgetCeiling := atomic.LoadInt64(&m.budgetCeiling)
	chain := atomic.LoadInt64(&m.chainLength)

	var avgLatency, denyRate, budgetPct float64
	if latCount > 0 {
		avgLatency = float64(latSum) / float64(latCount) / 1000.0
	}
	if dec > 0 {
		denyRate = float64(denials) / float64(dec) * 100.0
	}
	if budgetCeiling > 0 {
		budgetPct = float64(budgetUsed) / float64(budgetCeiling) * 100.0
	}

	m.mu.RLock()
	tools := make(map[string]int64, len(m.toolCounts))
	for k, v := range m.toolCounts {
		tools[k] = v
	}
	reasons := make(map[string]int64, len(m.reasonCounts))
	for k, v := range m.reasonCounts {
		reasons[k] = v
	}
	// Count active agents (seen in last 5 minutes).
	cutoff := time.Now().Add(-5 * time.Minute)
	active := 0
	for _, t := range m.activeAgents {
		if t.After(cutoff) {
			active++
		}
	}
	m.mu.RUnlock()

	return MetricsSnapshot{
		Decisions:    dec,
		Allows:       allows,
		Denials:      denials,
		DenyRate:     denyRate,
		AvgLatencyMs: avgLatency,
		ChainLength:  chain,
		ActiveAgents: active,
		BudgetUsed:   budgetPct,
		ToolCounts:   tools,
		ReasonCounts: reasons,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}
}

// Handler returns an http.HandlerFunc that serves metrics as JSON.
// Dashboard fetches from this endpoint.
// SEC: Wildcard CORS removed. Callers should use the auth.CORSMiddleware
// on the parent mux to set appropriate origin policies.
func (m *GovernanceMetrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m.Snapshot())
	}
}

// PrometheusHandler returns Prometheus text format metrics.
func (m *GovernanceMetrics) PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := m.Snapshot()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP helm_decisions_total Total governance decisions\n")
		fmt.Fprintf(w, "# TYPE helm_decisions_total counter\n")
		fmt.Fprintf(w, "helm_decisions_total %d\n", snap.Decisions)
		fmt.Fprintf(w, "# HELP helm_allows_total Total allowed decisions\n")
		fmt.Fprintf(w, "# TYPE helm_allows_total counter\n")
		fmt.Fprintf(w, "helm_allows_total %d\n", snap.Allows)
		fmt.Fprintf(w, "# HELP helm_denials_total Total denied decisions\n")
		fmt.Fprintf(w, "# TYPE helm_denials_total counter\n")
		fmt.Fprintf(w, "helm_denials_total %d\n", snap.Denials)
		fmt.Fprintf(w, "# HELP helm_decision_latency_ms Average decision latency\n")
		fmt.Fprintf(w, "# TYPE helm_decision_latency_ms gauge\n")
		fmt.Fprintf(w, "helm_decision_latency_ms %.3f\n", snap.AvgLatencyMs)
		fmt.Fprintf(w, "# HELP helm_chain_length Current receipt chain length\n")
		fmt.Fprintf(w, "# TYPE helm_chain_length gauge\n")
		fmt.Fprintf(w, "helm_chain_length %d\n", snap.ChainLength)
		fmt.Fprintf(w, "# HELP helm_active_agents Number of active agents\n")
		fmt.Fprintf(w, "# TYPE helm_active_agents gauge\n")
		fmt.Fprintf(w, "helm_active_agents %d\n", snap.ActiveAgents)
		fmt.Fprintf(w, "# HELP helm_budget_used_pct Budget utilization percentage\n")
		fmt.Fprintf(w, "# TYPE helm_budget_used_pct gauge\n")
		fmt.Fprintf(w, "helm_budget_used_pct %.1f\n", snap.BudgetUsed)
		for tool, count := range snap.ToolCounts {
			fmt.Fprintf(w, "helm_tool_decisions{tool=%q} %d\n", tool, count)
		}
		for reason, count := range snap.ReasonCounts {
			fmt.Fprintf(w, "helm_denial_reasons{reason=%q} %d\n", reason, count)
		}
	}
}
