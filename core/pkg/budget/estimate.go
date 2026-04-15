// estimate.go provides pre-execution cost estimation based on historical data.
// Before running a workflow, estimate total cost from similar past executions.
//
// Design invariants:
//   - Estimates based on moving average of recent executions
//   - Per-tool cost models maintained independently
//   - Thread-safe
//   - Returns both point estimate and confidence interval
package budget

import (
	"math"
	"sort"
	"sync"
)

const defaultMaxHistory = 100

// CostEstimate is the pre-execution cost prediction for a tool or workflow.
type CostEstimate struct {
	ToolName       string `json:"tool_name"`
	EstimatedCents int64  `json:"estimated_cents"`
	ConfidenceLow  int64  `json:"confidence_low"`  // p10
	ConfidenceHigh int64  `json:"confidence_high"` // p90
	SampleCount    int    `json:"sample_count"`
	ModelType      string `json:"model_type"` // "moving_average"
}

// EstimatorOption configures optional behavior for CostEstimator.
type EstimatorOption func(*CostEstimator)

// CostEstimator maintains per-tool cost histories and computes estimates
// using a moving average with percentile-based confidence intervals.
type CostEstimator struct {
	mu         sync.RWMutex
	history    map[string][]int64 // toolName -> recent costs (cents)
	maxHistory int
}

// NewCostEstimator creates a new estimator with the given options.
func NewCostEstimator(opts ...EstimatorOption) *CostEstimator {
	e := &CostEstimator{
		history:    make(map[string][]int64),
		maxHistory: defaultMaxHistory,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// WithMaxHistory sets the maximum number of historical observations to retain
// per tool. Older observations are discarded when the limit is reached.
func WithMaxHistory(n int) EstimatorOption {
	return func(e *CostEstimator) {
		if n > 0 {
			e.maxHistory = n
		}
	}
}

// RecordCost records an observed cost for a tool. If the history exceeds
// maxHistory, the oldest entry is discarded.
func (e *CostEstimator) RecordCost(toolName string, costCents int64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	h := e.history[toolName]
	h = append(h, costCents)
	if len(h) > e.maxHistory {
		h = h[len(h)-e.maxHistory:]
	}
	e.history[toolName] = h
}

// Estimate computes a cost estimate for a single tool based on its history.
// If no history exists, returns a zero estimate with zero samples.
func (e *CostEstimator) Estimate(toolName string) *CostEstimate {
	e.mu.RLock()
	defer e.mu.RUnlock()

	h := e.history[toolName]
	if len(h) == 0 {
		return &CostEstimate{
			ToolName:  toolName,
			ModelType: "moving_average",
		}
	}

	avg := mean(h)
	p10 := percentile(h, 10)
	p90 := percentile(h, 90)

	return &CostEstimate{
		ToolName:       toolName,
		EstimatedCents: avg,
		ConfidenceLow:  p10,
		ConfidenceHigh: p90,
		SampleCount:    len(h),
		ModelType:      "moving_average",
	}
}

// EstimateWorkflow sums estimates for a list of tools to produce a
// composite workflow estimate.
func (e *CostEstimator) EstimateWorkflow(tools []string) *CostEstimate {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := &CostEstimate{
		ToolName:  "workflow",
		ModelType: "moving_average",
	}

	for _, tool := range tools {
		h := e.history[tool]
		if len(h) == 0 {
			continue
		}
		result.EstimatedCents += mean(h)
		result.ConfidenceLow += percentile(h, 10)
		result.ConfidenceHigh += percentile(h, 90)
		result.SampleCount += len(h)
	}

	return result
}

// mean computes the arithmetic mean of a slice of int64 values.
func mean(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	var sum int64
	for _, v := range values {
		sum += v
	}
	return sum / int64(len(values))
}

// percentile computes the p-th percentile of a slice of int64 values
// using nearest-rank interpolation. The input slice is not modified.
func percentile(values []int64, p int) int64 {
	if len(values) == 0 {
		return 0
	}

	// Sort a copy to avoid mutating the original history.
	sorted := make([]int64, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}

	// Nearest-rank method.
	rank := int(math.Ceil(float64(p)/100.0*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}
