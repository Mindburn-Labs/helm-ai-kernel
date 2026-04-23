// Package observability — SLO Definitions + Tracker.
//
// Per HELM 2030 Spec — SLOs for All Runtime Operations:
//   - SLO definitions for: compile, plan, execute, verify, replay, escalation
//   - Burn-rate alerting: track how fast error budget is being consumed
//   - Real-time compliance tracking
package observability

import (
	"fmt"
	"sync"
	"time"
)

// SLOTarget defines a service level objective.
type SLOTarget struct {
	SLOID       string        `json:"slo_id"`
	Name        string        `json:"name"`
	Operation   string        `json:"operation"`    // compile, plan, execute, verify, replay, escalation
	LatencyP99  time.Duration `json:"latency_p99"`  // Target p99 latency
	SuccessRate float64       `json:"success_rate"` // Target success rate (0-1)
	WindowHours int           `json:"window_hours"` // Evaluation window
}

// SLOObservation is a single data point.
type SLOObservation struct {
	Operation string        `json:"operation"`
	Latency   time.Duration `json:"latency"`
	Success   bool          `json:"success"`
	Timestamp time.Time     `json:"timestamp"`
}

// SLOStatus reports current compliance.
type SLOStatus struct {
	SLOID            string  `json:"slo_id"`
	Operation        string  `json:"operation"`
	CurrentP99       float64 `json:"current_p99_ms"`
	CurrentSuccess   float64 `json:"current_success_rate"`
	InCompliance     bool    `json:"in_compliance"`
	BurnRate         float64 `json:"burn_rate"`         // >1 means burning faster than budget allows
	ErrorBudgetLeft  float64 `json:"error_budget_left"` // percentage remaining
	ObservationCount int     `json:"observation_count"`
}

// SLOTracker monitors SLOs across operations.
type SLOTracker struct {
	mu           sync.Mutex
	targets      map[string]*SLOTarget       // operation → target
	observations map[string][]SLOObservation // operation → observations
	clock        func() time.Time
}

// NewSLOTracker creates a new tracker.
func NewSLOTracker() *SLOTracker {
	return &SLOTracker{
		targets:      make(map[string]*SLOTarget),
		observations: make(map[string][]SLOObservation),
		clock:        time.Now,
	}
}

// WithClock overrides clock for testing.
func (t *SLOTracker) WithClock(clock func() time.Time) *SLOTracker {
	t.clock = clock
	return t
}

// SetTarget sets an SLO target for an operation.
func (t *SLOTracker) SetTarget(target *SLOTarget) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.targets[target.Operation] = target
}

// Record records an observation.
func (t *SLOTracker) Record(obs SLOObservation) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if obs.Timestamp.IsZero() {
		obs.Timestamp = t.clock()
	}
	t.observations[obs.Operation] = append(t.observations[obs.Operation], obs)
}

// Status computes current SLO status for an operation.
func (t *SLOTracker) Status(operation string) (*SLOStatus, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	target, ok := t.targets[operation]
	if !ok {
		return nil, fmt.Errorf("no SLO target for operation %q", operation)
	}

	observations := t.observations[operation]
	now := t.clock()
	windowStart := now.Add(-time.Duration(target.WindowHours) * time.Hour)

	// Filter to window
	var windowed []SLOObservation
	for _, obs := range observations {
		if obs.Timestamp.After(windowStart) {
			windowed = append(windowed, obs)
		}
	}

	if len(windowed) == 0 {
		return &SLOStatus{
			SLOID:            target.SLOID,
			Operation:        operation,
			InCompliance:     true,
			ErrorBudgetLeft:  100.0,
			ObservationCount: 0,
		}, nil
	}

	// Compute success rate
	successCount := 0
	for _, obs := range windowed {
		if obs.Success {
			successCount++
		}
	}
	successRate := float64(successCount) / float64(len(windowed))

	// Compute p99 latency (approximate)
	latencies := make([]float64, len(windowed))
	for i, obs := range windowed {
		latencies[i] = float64(obs.Latency.Milliseconds())
	}
	// Sort for p99
	for i := range latencies {
		for j := i + 1; j < len(latencies); j++ {
			if latencies[j] < latencies[i] {
				latencies[i], latencies[j] = latencies[j], latencies[i]
			}
		}
	}
	p99Index := int(float64(len(latencies)) * 0.99)
	if p99Index >= len(latencies) {
		p99Index = len(latencies) - 1
	}
	p99 := latencies[p99Index]

	// Check compliance
	latencyOK := p99 <= float64(target.LatencyP99.Milliseconds())
	successOK := successRate >= target.SuccessRate
	inCompliance := latencyOK && successOK

	// Compute error budget and burn rate
	errorBudget := 1.0 - target.SuccessRate
	errorRate := 1.0 - successRate
	var burnRate float64
	if errorBudget > 0 {
		burnRate = errorRate / errorBudget
	}
	budgetLeft := 100.0 * (1.0 - (errorRate / errorBudget))
	if budgetLeft < 0 {
		budgetLeft = 0
	}

	return &SLOStatus{
		SLOID:            target.SLOID,
		Operation:        operation,
		CurrentP99:       p99,
		CurrentSuccess:   successRate,
		InCompliance:     inCompliance,
		BurnRate:         burnRate,
		ErrorBudgetLeft:  budgetLeft,
		ObservationCount: len(windowed),
	}, nil
}
