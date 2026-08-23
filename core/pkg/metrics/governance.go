// Package metrics provides a Prometheus-compatible metrics endpoint.
package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// GovernanceMetrics tracks governance decision metrics.
type GovernanceMetrics struct {
	mu             sync.RWMutex
	decisions      int64
	allows         int64
	denials        int64
	verifications  int64
	latencySum     int64 // microseconds
	latencyCount   int64
	toolCounts     map[string]int64
	reasonCounts   map[string]int64
	activeAgents   map[string]time.Time
	now            func() time.Time
	nextAgentSweep time.Time
	budgetUsed     int64
	budgetCeiling  int64
	chainLength    int64
	latencySamples []int64 // bounded recent decision latencies in microseconds
	latencyNext    int
}

// Label-cardinality bounds (HELM-301). The `tool` label value arrives from
// callers (with the pilot: connector-supplied names), and unlike reason_code
// it has no typed registry to validate against — so the collector itself
// enforces the bound: values are charset/length-sanitized and at most
// maxToolLabelValues distinct tools are tracked, with overflow collapsed into
// toolLabelOverflow. This keeps /metrics cardinality finite no matter what
// arrives at RecordDecision.
const (
	maxToolLabelValues = 64
	maxToolLabelLen    = 64
	toolLabelOverflow  = "_other"

	activeAgentWindow         = 5 * time.Minute
	activeAgentRetention      = 10 * time.Minute
	activeAgentSweepInterval  = time.Minute
	activeAgentSweepThreshold = 1024
)

// sanitizeToolLabel maps an arbitrary caller-supplied tool name onto the
// bounded label vocabulary: printable ASCII minus `"` and `\` (the two
// characters with meaning inside a quoted Prometheus label), truncated to
// maxToolLabelLen; empty input becomes the overflow bucket.
func sanitizeToolLabel(tool string) string {
	if tool == "" {
		return toolLabelOverflow
	}
	b := make([]byte, 0, len(tool))
	for i := 0; i < len(tool) && len(b) < maxToolLabelLen; i++ {
		c := tool[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			c = '_'
		}
		b = append(b, c)
	}
	return string(b)
}

// NewGovernanceMetrics creates a new metrics collector.
func NewGovernanceMetrics() *GovernanceMetrics {
	return &GovernanceMetrics{
		toolCounts:   make(map[string]int64),
		reasonCounts: make(map[string]int64),
		activeAgents: make(map[string]time.Time),
		now:          time.Now,
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
	tool = sanitizeToolLabel(tool)
	if _, seen := m.toolCounts[tool]; !seen && len(m.toolCounts) >= maxToolLabelValues {
		tool = toolLabelOverflow
	}
	m.toolCounts[tool]++
	if reasonCode != "" {
		m.reasonCounts[reasonCode]++
	}
	now := m.now()
	m.activeAgents[agentID] = now
	// HELM-302: evict idle agents opportunistically so a long-lived kernel
	// does not accumulate every agent id ever seen. The snapshot's activity
	// window is 5 minutes; anything past 10 is dead weight. Throttling avoids
	// scanning the map on every decision while it remains above the threshold.
	if len(m.activeAgents) > activeAgentSweepThreshold && !now.Before(m.nextAgentSweep) {
		cutoff := now.Add(-activeAgentRetention)
		for id, seen := range m.activeAgents {
			if seen.Before(cutoff) {
				delete(m.activeAgents, id)
			}
		}
		m.nextAgentSweep = now.Add(activeAgentSweepInterval)
	}
	if len(m.latencySamples) < 1024 {
		m.latencySamples = append(m.latencySamples, latencyUs)
	} else {
		m.latencySamples[m.latencyNext] = latencyUs
		m.latencyNext = (m.latencyNext + 1) % len(m.latencySamples)
	}
	m.mu.Unlock()
}

// RecordVerification records one EvidencePack verification run against this
// instance. Verifications by parties other than the operator are the
// north-star adoption metric (see docs: the category is won when receipts are
// verified by auditors, customers, and counterparties — not just produced).
func (m *GovernanceMetrics) RecordVerification() {
	atomic.AddInt64(&m.verifications, 1)
}

// SetBudget updates budget tracking.
func (m *GovernanceMetrics) SetBudget(used, ceiling int64) {
	atomic.StoreInt64(&m.budgetUsed, used)
	atomic.StoreInt64(&m.budgetCeiling, ceiling)
}

// Snapshot returns a point-in-time metrics snapshot.
type MetricsSnapshot struct {
	Decisions     int64            `json:"decisions_total"`
	Allows        int64            `json:"allows_total"`
	Denials       int64            `json:"denials_total"`
	Verifications int64            `json:"verifications_total"`
	DenyRate      float64          `json:"deny_rate"`
	AvgLatencyMs  float64          `json:"avg_latency_ms"`
	P95LatencyMs  float64          `json:"p95_latency_ms"`
	P99LatencyMs  float64          `json:"p99_latency_ms"`
	ChainLength   int64            `json:"chain_length"`
	ActiveAgents  int              `json:"active_agents"`
	BudgetUsed    float64          `json:"budget_used_pct"`
	ToolCounts    map[string]int64 `json:"tool_counts"`
	ReasonCounts  map[string]int64 `json:"reason_counts"`
	Timestamp     string           `json:"timestamp"`
}

// Snapshot returns current metrics.
func (m *GovernanceMetrics) Snapshot() MetricsSnapshot {
	dec := atomic.LoadInt64(&m.decisions)
	allows := atomic.LoadInt64(&m.allows)
	denials := atomic.LoadInt64(&m.denials)
	verifications := atomic.LoadInt64(&m.verifications)
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

	now := m.now()
	m.mu.RLock()
	tools := make(map[string]int64, len(m.toolCounts))
	for k, v := range m.toolCounts {
		tools[k] = v
	}
	reasons := make(map[string]int64, len(m.reasonCounts))
	for k, v := range m.reasonCounts {
		reasons[k] = v
	}
	samples := append([]int64(nil), m.latencySamples...)
	// Count active agents seen within the source-owned activity window.
	cutoff := now.Add(-activeAgentWindow)
	active := 0
	for _, t := range m.activeAgents {
		if t.After(cutoff) {
			active++
		}
	}
	m.mu.RUnlock()

	return MetricsSnapshot{
		Decisions:     dec,
		Allows:        allows,
		Denials:       denials,
		Verifications: verifications,
		DenyRate:      denyRate,
		AvgLatencyMs:  avgLatency,
		P95LatencyMs:  latencyQuantileMs(samples, 0.95),
		P99LatencyMs:  latencyQuantileMs(samples, 0.99),
		ChainLength:   chain,
		ActiveAgents:  active,
		BudgetUsed:    budgetPct,
		ToolCounts:    tools,
		ReasonCounts:  reasons,
		Timestamp:     now.UTC().Format(time.RFC3339),
	}
}

func latencyQuantileMs(samples []int64, q float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	idx := int(float64(len(samples)-1) * q)
	return float64(samples[idx]) / 1000.0
}

// Handler returns an http.HandlerFunc that serves metrics as JSON.
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
		fmt.Fprintf(w, "# HELP helm_verifications_total EvidencePack verifications run (north-star adoption metric)\n")
		fmt.Fprintf(w, "# TYPE helm_verifications_total counter\n")
		fmt.Fprintf(w, "helm_verifications_total %d\n", snap.Verifications)
		fmt.Fprintf(w, "# HELP helm_decision_latency_ms Average decision latency\n")
		fmt.Fprintf(w, "# TYPE helm_decision_latency_ms gauge\n")
		fmt.Fprintf(w, "helm_decision_latency_ms %.3f\n", snap.AvgLatencyMs)
		fmt.Fprintf(w, "# HELP helm_decision_latency_p95_ms Recent p95 decision latency\n")
		fmt.Fprintf(w, "# TYPE helm_decision_latency_p95_ms gauge\n")
		fmt.Fprintf(w, "helm_decision_latency_p95_ms %.3f\n", snap.P95LatencyMs)
		fmt.Fprintf(w, "# HELP helm_decision_latency_p99_ms Recent p99 decision latency\n")
		fmt.Fprintf(w, "# TYPE helm_decision_latency_p99_ms gauge\n")
		fmt.Fprintf(w, "helm_decision_latency_p99_ms %.3f\n", snap.P99LatencyMs)
		fmt.Fprintf(w, "# HELP helm_chain_length Current receipt chain length\n")
		fmt.Fprintf(w, "# TYPE helm_chain_length gauge\n")
		fmt.Fprintf(w, "helm_chain_length %d\n", snap.ChainLength)
		fmt.Fprintf(w, "# HELP helm_active_agents Number of agents seen in the last 5 minutes\n")
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

// PrometheusCollector exposes the bounded governance snapshot as a collector
// so callers can compose it with other registries before promhttp encodes a
// response. This keeps OpenMetrics' terminal # EOF marker last on the wire.
func (m *GovernanceMetrics) PrometheusCollector() prometheus.Collector {
	return &governanceCollector{metrics: m}
}

// PrometheusGatherer returns an isolated registry containing this collector.
// It is used when governance metrics must be encoded alongside another
// registry in one scrape response.
func (m *GovernanceMetrics) PrometheusGatherer() prometheus.Gatherer {
	registry := prometheus.NewRegistry()
	registry.MustRegister(m.PrometheusCollector())
	return registry
}

type governanceCollector struct {
	metrics *GovernanceMetrics
}

func (c *governanceCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("helm_decisions_total", "Total governance decisions", nil, nil)
	ch <- prometheus.NewDesc("helm_allows_total", "Total allowed decisions", nil, nil)
	ch <- prometheus.NewDesc("helm_denials_total", "Total denied decisions", nil, nil)
	ch <- prometheus.NewDesc("helm_verifications_total", "EvidencePack verifications run (north-star adoption metric)", nil, nil)
	ch <- prometheus.NewDesc("helm_decision_latency_ms", "Average decision latency", nil, nil)
	ch <- prometheus.NewDesc("helm_decision_latency_p95_ms", "Recent p95 decision latency", nil, nil)
	ch <- prometheus.NewDesc("helm_decision_latency_p99_ms", "Recent p99 decision latency", nil, nil)
	ch <- prometheus.NewDesc("helm_chain_length", "Current receipt chain length", nil, nil)
	ch <- prometheus.NewDesc("helm_active_agents", "Number of agents seen in the last 5 minutes", nil, nil)
	ch <- prometheus.NewDesc("helm_budget_used_pct", "Budget utilization percentage", nil, nil)
	ch <- prometheus.NewDesc("helm_tool_decisions", "Governance decisions by tool", []string{"tool"}, nil)
	ch <- prometheus.NewDesc("helm_denial_reasons", "Governance denials by reason", []string{"reason"}, nil)
}

func (c *governanceCollector) Collect(ch chan<- prometheus.Metric) {
	if c == nil || c.metrics == nil {
		return
	}
	snap := c.metrics.Snapshot()
	constMetric := func(name, help string, valueType prometheus.ValueType, value float64) {
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc(name, help, nil, nil), valueType, value)
	}
	constMetric("helm_decisions_total", "Total governance decisions", prometheus.CounterValue, float64(snap.Decisions))
	constMetric("helm_allows_total", "Total allowed decisions", prometheus.CounterValue, float64(snap.Allows))
	constMetric("helm_denials_total", "Total denied decisions", prometheus.CounterValue, float64(snap.Denials))
	constMetric("helm_verifications_total", "EvidencePack verifications run (north-star adoption metric)", prometheus.CounterValue, float64(snap.Verifications))
	constMetric("helm_decision_latency_ms", "Average decision latency", prometheus.GaugeValue, snap.AvgLatencyMs)
	constMetric("helm_decision_latency_p95_ms", "Recent p95 decision latency", prometheus.GaugeValue, snap.P95LatencyMs)
	constMetric("helm_decision_latency_p99_ms", "Recent p99 decision latency", prometheus.GaugeValue, snap.P99LatencyMs)
	constMetric("helm_chain_length", "Current receipt chain length", prometheus.GaugeValue, float64(snap.ChainLength))
	constMetric("helm_active_agents", "Number of agents seen in the last 5 minutes", prometheus.GaugeValue, float64(snap.ActiveAgents))
	constMetric("helm_budget_used_pct", "Budget utilization percentage", prometheus.GaugeValue, snap.BudgetUsed)
	toolDesc := prometheus.NewDesc("helm_tool_decisions", "Governance decisions by tool", []string{"tool"}, nil)
	for tool, count := range snap.ToolCounts {
		ch <- prometheus.MustNewConstMetric(toolDesc, prometheus.GaugeValue, float64(count), tool)
	}
	reasonDesc := prometheus.NewDesc("helm_denial_reasons", "Governance denials by reason", []string{"reason"}, nil)
	for reason, count := range snap.ReasonCounts {
		ch <- prometheus.MustNewConstMetric(reasonDesc, prometheus.GaugeValue, float64(count), reason)
	}
}
