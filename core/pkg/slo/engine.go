// Package slo implements service level objective tracking for HELM governance.
// It tracks decision latency SLOs and error budget consumption.
//
// Design invariants:
//   - SLOs are defined per-metric (latency, error rate)
//   - Error budgets track remaining allowance within a window
//   - Thread-safe for concurrent decision recording
//   - Budget exhaustion triggers alerts (callback)
//   - All measurements use monotonic clock for accuracy
//   - Events outside the rolling window are excluded from budget calculations
package slo

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// MetricType classifies the kind of SLO being tracked.
type MetricType string

const (
	// MetricTypeLatency tracks whether decisions complete within a latency bound.
	MetricTypeLatency MetricType = "LATENCY"
	// MetricTypeErrorRate tracks the ratio of successful to total decisions.
	MetricTypeErrorRate MetricType = "ERROR_RATE"
)

// Objective defines a service level objective.
type Objective struct {
	// Name uniquely identifies this SLO.
	Name string `json:"name"`
	// Target is the compliance fraction, e.g., 0.999 for 99.9%.
	Target float64 `json:"target"`
	// Window is the rolling window over which the SLO is evaluated.
	Window time.Duration `json:"window"`
	// MetricType indicates whether this SLO tracks latency or error rate.
	MetricType MetricType `json:"metric_type"`
	// LatencyBound is the maximum acceptable latency for LATENCY SLOs.
	// Ignored for ERROR_RATE SLOs.
	LatencyBound time.Duration `json:"latency_bound"`
}

// BudgetStatus reports the current state of an SLO's error budget.
type BudgetStatus struct {
	// ObjectiveName is the name of the tracked SLO.
	ObjectiveName string `json:"objective_name"`
	// Target is the SLO target (e.g., 0.999).
	Target float64 `json:"target"`
	// Current is the current compliance rate within the window.
	Current float64 `json:"current"`
	// Remaining is the fraction of error budget remaining (0.0-1.0).
	// 1.0 means no errors consumed, 0.0 means budget is exhausted.
	Remaining float64 `json:"remaining"`
	// TotalEvents is the number of events within the window.
	TotalEvents int64 `json:"total_events"`
	// GoodEvents is the number of events meeting the SLO within the window.
	GoodEvents int64 `json:"good_events"`
	// BadEvents is the number of events violating the SLO within the window.
	BadEvents int64 `json:"bad_events"`
	// WindowStart is the beginning of the current evaluation window.
	WindowStart time.Time `json:"window_start"`
	// Exhausted indicates whether the error budget has been fully consumed.
	Exhausted bool `json:"exhausted"`
}

// EngineOption configures optional Engine settings.
type EngineOption func(*Engine)

// Engine tracks SLO objectives and computes error budget status.
type Engine struct {
	mu          sync.RWMutex
	objectives  map[string]*trackedObjective
	clock       func() time.Time
	onExhausted func(status BudgetStatus) // Callback when budget exhausted.
}

// trackedObjective pairs an SLO definition with its recorded events.
type trackedObjective struct {
	objective Objective
	events    []event
}

// event is a single recorded measurement.
type event struct {
	timestamp time.Time
	good      bool
	latency   time.Duration
}

// ErrObjectiveNotFound is returned when an operation references an unknown SLO name.
type ErrObjectiveNotFound struct {
	Name string
}

// Error implements the error interface.
func (e *ErrObjectiveNotFound) Error() string {
	return fmt.Sprintf("slo: objective %q not found", e.Name)
}

// ErrDuplicateObjective is returned when registering an SLO name that already exists.
type ErrDuplicateObjective struct {
	Name string
}

// Error implements the error interface.
func (e *ErrDuplicateObjective) Error() string {
	return fmt.Sprintf("slo: objective %q already registered", e.Name)
}

// ErrInvalidObjective is returned when an SLO definition fails validation.
type ErrInvalidObjective struct {
	Name   string
	Reason string
}

// Error implements the error interface.
func (e *ErrInvalidObjective) Error() string {
	return fmt.Sprintf("slo: invalid objective %q: %s", e.Name, e.Reason)
}

// NewEngine creates a new SLO tracking engine with the given options.
func NewEngine(opts ...EngineOption) *Engine {
	e := &Engine{
		objectives: make(map[string]*trackedObjective),
		clock:      time.Now,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// WithEngineClock injects a deterministic clock for testing.
func WithEngineClock(clock func() time.Time) EngineOption {
	return func(e *Engine) {
		e.clock = clock
	}
}

// WithExhaustedCallback sets a callback invoked when an SLO's error budget
// is exhausted. The callback is invoked under the engine's write lock, so it
// must not call back into the engine.
func WithExhaustedCallback(cb func(status BudgetStatus)) EngineOption {
	return func(e *Engine) {
		e.onExhausted = cb
	}
}

// Register adds an SLO objective to the engine. Returns an error if the
// objective name is empty, already registered, or the definition is invalid.
func (e *Engine) Register(obj Objective) error {
	if obj.Name == "" {
		return &ErrInvalidObjective{Name: "", Reason: "name is required"}
	}
	if obj.Target <= 0 || obj.Target > 1 {
		return &ErrInvalidObjective{Name: obj.Name, Reason: "target must be in (0, 1]"}
	}
	if obj.Window <= 0 {
		return &ErrInvalidObjective{Name: obj.Name, Reason: "window must be positive"}
	}
	if obj.MetricType != MetricTypeLatency && obj.MetricType != MetricTypeErrorRate {
		return &ErrInvalidObjective{Name: obj.Name, Reason: fmt.Sprintf("unknown metric type %q", obj.MetricType)}
	}
	if obj.MetricType == MetricTypeLatency && obj.LatencyBound <= 0 {
		return &ErrInvalidObjective{Name: obj.Name, Reason: "latency_bound must be positive for LATENCY metrics"}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.objectives[obj.Name]; exists {
		return &ErrDuplicateObjective{Name: obj.Name}
	}

	e.objectives[obj.Name] = &trackedObjective{
		objective: obj,
		events:    nil,
	}

	slog.Debug("slo: objective registered",
		"name", obj.Name,
		"target", obj.Target,
		"window", obj.Window,
		"metric_type", obj.MetricType,
	)

	return nil
}

// RecordLatency records a latency measurement for a LATENCY SLO.
// The event is classified as "good" if latency <= LatencyBound.
// If the objective is not found or is not a LATENCY SLO, the call is a no-op
// and a warning is logged.
func (e *Engine) RecordLatency(objectiveName string, latency time.Duration) {
	now := e.clock()

	e.mu.Lock()
	defer e.mu.Unlock()

	tracked, ok := e.objectives[objectiveName]
	if !ok {
		slog.Warn("slo: RecordLatency for unknown objective", "name", objectiveName)
		return
	}
	if tracked.objective.MetricType != MetricTypeLatency {
		slog.Warn("slo: RecordLatency called on non-latency objective",
			"name", objectiveName,
			"metric_type", tracked.objective.MetricType,
		)
		return
	}

	good := latency <= tracked.objective.LatencyBound
	tracked.events = append(tracked.events, event{
		timestamp: now,
		good:      good,
		latency:   latency,
	})

	e.checkExhaustionLocked(tracked, now)
}

// RecordOutcome records a success/failure outcome for an ERROR_RATE SLO.
// If the objective is not found or is not an ERROR_RATE SLO, the call is a no-op
// and a warning is logged.
func (e *Engine) RecordOutcome(objectiveName string, success bool) {
	now := e.clock()

	e.mu.Lock()
	defer e.mu.Unlock()

	tracked, ok := e.objectives[objectiveName]
	if !ok {
		slog.Warn("slo: RecordOutcome for unknown objective", "name", objectiveName)
		return
	}
	if tracked.objective.MetricType != MetricTypeErrorRate {
		slog.Warn("slo: RecordOutcome called on non-error-rate objective",
			"name", objectiveName,
			"metric_type", tracked.objective.MetricType,
		)
		return
	}

	tracked.events = append(tracked.events, event{
		timestamp: now,
		good:      success,
	})

	e.checkExhaustionLocked(tracked, now)
}

// Status returns the current error budget status for the named SLO.
// Returns ErrObjectiveNotFound if the name is not registered.
func (e *Engine) Status(objectiveName string) (*BudgetStatus, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	tracked, ok := e.objectives[objectiveName]
	if !ok {
		return nil, &ErrObjectiveNotFound{Name: objectiveName}
	}

	now := e.clock()
	return e.computeStatusLocked(tracked, now), nil
}

// AllStatuses returns the current budget status for all registered SLOs,
// sorted by objective name for deterministic output.
func (e *Engine) AllStatuses() []BudgetStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := e.clock()
	statuses := make([]BudgetStatus, 0, len(e.objectives))
	for _, tracked := range e.objectives {
		statuses = append(statuses, *e.computeStatusLocked(tracked, now))
	}

	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].ObjectiveName < statuses[j].ObjectiveName
	})

	return statuses
}

// computeStatusLocked calculates the budget status. Must be called under at least a read lock.
func (e *Engine) computeStatusLocked(tracked *trackedObjective, now time.Time) *BudgetStatus {
	obj := tracked.objective
	windowStart := now.Add(-obj.Window)

	var good, bad int64
	for _, ev := range tracked.events {
		if ev.timestamp.Before(windowStart) {
			continue
		}
		if ev.good {
			good++
		} else {
			bad++
		}
	}

	total := good + bad
	var current float64
	if total > 0 {
		current = float64(good) / float64(total)
	} else {
		// No events — compliance is perfect by definition.
		current = 1.0
	}

	// Error budget: the allowed fraction of bad events is (1 - target).
	// Remaining = 1 - (bad / (total * (1 - target))).
	// Clamped to [0, 1].
	var remaining float64
	errorBudgetTotal := float64(total) * (1 - obj.Target)
	if total == 0 || errorBudgetTotal <= 0 {
		remaining = 1.0
	} else {
		consumed := float64(bad) / errorBudgetTotal
		remaining = 1.0 - consumed
		if remaining < 0 {
			remaining = 0
		}
		if remaining > 1 {
			remaining = 1
		}
	}

	exhausted := total > 0 && remaining <= 0

	return &BudgetStatus{
		ObjectiveName: obj.Name,
		Target:        obj.Target,
		Current:       current,
		Remaining:     remaining,
		TotalEvents:   total,
		GoodEvents:    good,
		BadEvents:     bad,
		WindowStart:   windowStart,
		Exhausted:     exhausted,
	}
}

// checkExhaustionLocked fires the exhaustion callback if the budget is now exhausted.
// Must be called under the write lock.
func (e *Engine) checkExhaustionLocked(tracked *trackedObjective, now time.Time) {
	if e.onExhausted == nil {
		return
	}

	status := e.computeStatusLocked(tracked, now)
	if status.Exhausted {
		slog.Warn("slo: error budget exhausted",
			"objective", status.ObjectiveName,
			"current", status.Current,
			"target", status.Target,
			"bad_events", status.BadEvents,
			"total_events", status.TotalEvents,
		)
		e.onExhausted(*status)
	}
}
