// Package kernel provides evaluation windowing for essential variables.
// Per Section 4.1 - EssentialVariable Schema
package kernel

import (
	"sync"
	"time"
)

// EvaluationWindow tracks values over a rolling window.
type EvaluationWindow struct {
	mu         sync.RWMutex
	windowSize time.Duration
	samples    []windowSample
	maxSamples int
}

type windowSample struct {
	Value     float64
	Timestamp time.Time
}

// NewEvaluationWindow creates a new evaluation window.
func NewEvaluationWindow(windowSize time.Duration, maxSamples int) *EvaluationWindow {
	return &EvaluationWindow{
		windowSize: windowSize,
		samples:    make([]windowSample, 0),
		maxSamples: maxSamples,
	}
}

// Add adds a sample to the window.
func (w *EvaluationWindow) Add(value float64, timestamp time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.samples = append(w.samples, windowSample{Value: value, Timestamp: timestamp})

	// Prune old samples and enforce max
	w.prune(timestamp)
}

func (w *EvaluationWindow) prune(now time.Time) {
	cutoff := now.Add(-w.windowSize)

	// Find first sample within window
	start := 0
	for i, s := range w.samples {
		if s.Timestamp.After(cutoff) {
			start = i
			break
		}
		if i == len(w.samples)-1 {
			start = len(w.samples) // All samples are old
		}
	}

	w.samples = w.samples[start:]

	// Enforce max samples
	if len(w.samples) > w.maxSamples {
		w.samples = w.samples[len(w.samples)-w.maxSamples:]
	}
}

// Average returns the average value in the window.
func (w *EvaluationWindow) Average() float64 {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if len(w.samples) == 0 {
		return 0
	}

	var sum float64
	for _, s := range w.samples {
		sum += s.Value
	}
	return sum / float64(len(w.samples))
}

// Min returns the minimum value in the window.
func (w *EvaluationWindow) Min() float64 {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if len(w.samples) == 0 {
		return 0
	}

	min := w.samples[0].Value
	for _, s := range w.samples[1:] {
		if s.Value < min {
			min = s.Value
		}
	}
	return min
}

// Max returns the maximum value in the window.
func (w *EvaluationWindow) Max() float64 {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if len(w.samples) == 0 {
		return 0
	}

	max := w.samples[0].Value
	for _, s := range w.samples[1:] {
		if s.Value > max {
			max = s.Value
		}
	}
	return max
}

// Count returns the number of samples in the window.
func (w *EvaluationWindow) Count() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.samples)
}

// ViolationAction defines what to do when a variable violates its bounds.
type ViolationAction string

const (
	ViolationActionAlert  ViolationAction = "ALERT"
	ViolationActionClamp  ViolationAction = "CLAMP"
	ViolationActionHalt   ViolationAction = "HALT"
	ViolationActionRevert ViolationAction = "REVERT"
)

// ViolationTrigger handles essential variable violations.
type ViolationTrigger struct {
	VariableID    string
	Action        ViolationAction
	ThresholdType string // "min", "max", "range"
	MinThreshold  float64
	MaxThreshold  float64
	Handler       ViolationHandler
}

// ViolationHandler processes violations.
type ViolationHandler interface {
	HandleViolation(trigger *ViolationTrigger, currentValue float64) error
}

// Check checks if a value violates the trigger's bounds.
func (t *ViolationTrigger) Check(value float64) (bool, string) {
	switch t.ThresholdType {
	case "min":
		if value < t.MinThreshold {
			return true, "below_minimum"
		}
	case "max":
		if value > t.MaxThreshold {
			return true, "above_maximum"
		}
	case "range":
		if value < t.MinThreshold {
			return true, "below_minimum"
		}
		if value > t.MaxThreshold {
			return true, "above_maximum"
		}
	}
	return false, ""
}

// Execute executes the violation action.
func (t *ViolationTrigger) Execute(value float64) error {
	if t.Handler == nil {
		return nil
	}
	return t.Handler.HandleViolation(t, value)
}

// EssentialVariableMonitor monitors essential variables with windowing and triggers.
type EssentialVariableMonitor struct {
	mu       sync.RWMutex
	windows  map[string]*EvaluationWindow
	triggers map[string][]*ViolationTrigger
}

// NewEssentialVariableMonitor creates a new monitor.
func NewEssentialVariableMonitor() *EssentialVariableMonitor {
	return &EssentialVariableMonitor{
		windows:  make(map[string]*EvaluationWindow),
		triggers: make(map[string][]*ViolationTrigger),
	}
}

// RegisterVariable registers a variable with a window.
func (m *EssentialVariableMonitor) RegisterVariable(variableID string, windowSize time.Duration, maxSamples int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.windows[variableID] = NewEvaluationWindow(windowSize, maxSamples)
}

// AddTrigger adds a violation trigger for a variable.
func (m *EssentialVariableMonitor) AddTrigger(trigger *ViolationTrigger) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.triggers[trigger.VariableID] = append(m.triggers[trigger.VariableID], trigger)
}

// RecordValue records a value and checks triggers.
func (m *EssentialVariableMonitor) RecordValue(variableID string, value float64, timestamp time.Time) []error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Record value
	if window, exists := m.windows[variableID]; exists {
		window.Add(value, timestamp)
	}

	// Check triggers
	var errors []error
	for _, trigger := range m.triggers[variableID] {
		violated, _ := trigger.Check(value)
		if violated {
			if err := trigger.Execute(value); err != nil {
				errors = append(errors, err)
			}
		}
	}

	return errors
}

// GetStatistics returns windowed statistics for a variable.
func (m *EssentialVariableMonitor) GetStatistics(variableID string) (avg, min, max float64, count int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	window, exists := m.windows[variableID]
	if !exists {
		return 0, 0, 0, 0
	}

	return window.Average(), window.Min(), window.Max(), window.Count()
}
