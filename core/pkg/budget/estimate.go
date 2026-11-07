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
