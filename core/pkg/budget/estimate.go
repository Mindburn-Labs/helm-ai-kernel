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

// CostEstimator preserves the type of the retired cost estimator.
type CostEstimator struct {
	mu         sync.RWMutex
	history    map[string][]int64 // toolName -> recent costs (cents)
	maxHistory int
}
