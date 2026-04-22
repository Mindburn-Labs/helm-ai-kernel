// Package envelope — EnvelopeMonitor.
//
// Per HELM 2030 Spec §2:
//
//	Autonomy default means: envelope pre-approved, continuously monitored,
//	and continuously enforced; anything outside becomes an exception.
package envelope

import (
	"fmt"
	"sync"
	"time"
)

// ViolationType categorizes envelope violations.
type ViolationType string

const (
	ViolationExpired      ViolationType = "EXPIRED"
	ViolationBudget       ViolationType = "BUDGET_EXCEEDED"
	ViolationScope        ViolationType = "SCOPE_EXCEEDED"
	ViolationJurisdiction ViolationType = "JURISDICTION_VIOLATION"
	ViolationEffect       ViolationType = "DISALLOWED_EFFECT"
)

// Violation records a detected envelope violation.
type Violation struct {
	ViolationID string        `json:"violation_id"`
	EnvelopeID  string        `json:"envelope_id"`
	Type        ViolationType `json:"type"`
	Description string        `json:"description"`
	DetectedAt  time.Time     `json:"detected_at"`
	AutoPaused  bool          `json:"auto_paused"`
}

// MonitoredEnvelope wraps an envelope for continuous monitoring.
type MonitoredEnvelope struct {
	EnvelopeID string
	ValidUntil time.Time
	BudgetMax  float64
	BudgetUsed float64
	Active     bool
}

// EnvelopeMonitor continuously enforces envelope constraints.
type EnvelopeMonitor struct {
	mu         sync.Mutex
	envelopes  map[string]*MonitoredEnvelope
	violations []Violation
	onPause    func(envelopeID, reason string) // callback for auto-pause
	seq        int64
	clock      func() time.Time
}

// NewEnvelopeMonitor creates a new monitor.
func NewEnvelopeMonitor() *EnvelopeMonitor {
	return &EnvelopeMonitor{
		envelopes: make(map[string]*MonitoredEnvelope),
		clock:     time.Now,
	}
}

// WithClock overrides clock for testing.
func (m *EnvelopeMonitor) WithClock(clock func() time.Time) *EnvelopeMonitor {
	m.clock = clock
	return m
}

// OnPause sets the callback invoked when auto-pause triggers.
func (m *EnvelopeMonitor) OnPause(fn func(envelopeID, reason string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPause = fn
}

// Watch registers an envelope for continuous monitoring.
func (m *EnvelopeMonitor) Watch(env *MonitoredEnvelope) {
	m.mu.Lock()
	defer m.mu.Unlock()
	env.Active = true
	m.envelopes[env.EnvelopeID] = env
}

// RecordUsage records budget usage for an envelope.
func (m *EnvelopeMonitor) RecordUsage(envelopeID string, cost float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	env, ok := m.envelopes[envelopeID]
	if !ok {
		return fmt.Errorf("envelope %q not monitored", envelopeID)
	}

	env.BudgetUsed += cost

	if env.BudgetUsed > env.BudgetMax {
		m.recordViolation(envelopeID, ViolationBudget, fmt.Sprintf("budget %.2f > max %.2f", env.BudgetUsed, env.BudgetMax))
		return fmt.Errorf("budget exceeded for envelope %q", envelopeID)
	}
	return nil
}

// Check performs a point-in-time enforcement check on all monitored envelopes.
func (m *EnvelopeMonitor) Check() []Violation {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()
	var newViolations []Violation

	for id, env := range m.envelopes {
		if !env.Active {
			continue
		}
		// Expiry check
		if !env.ValidUntil.IsZero() && now.After(env.ValidUntil) {
			v := m.recordViolation(id, ViolationExpired, "envelope expired")
			newViolations = append(newViolations, v)
		}
		// Budget check
		if env.BudgetUsed > env.BudgetMax {
			v := m.recordViolation(id, ViolationBudget, fmt.Sprintf("budget %.2f > max %.2f", env.BudgetUsed, env.BudgetMax))
			newViolations = append(newViolations, v)
		}
	}

	return newViolations
}

func (m *EnvelopeMonitor) recordViolation(envelopeID string, vType ViolationType, description string) Violation {
	m.seq++
	v := Violation{
		ViolationID: fmt.Sprintf("viol-%d", m.seq),
		EnvelopeID:  envelopeID,
		Type:        vType,
		Description: description,
		DetectedAt:  m.clock(),
		AutoPaused:  true,
	}

	m.violations = append(m.violations, v)

	// Auto-pause: deactivate envelope
	if env, ok := m.envelopes[envelopeID]; ok {
		env.Active = false
	}

	if m.onPause != nil {
		m.onPause(envelopeID, description)
	}

	return v
}

// IsActive returns whether an envelope is currently active and valid.
func (m *EnvelopeMonitor) IsActive(envelopeID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	env, ok := m.envelopes[envelopeID]
	if !ok {
		return false
	}
	return env.Active
}

// Violations returns all recorded violations.
func (m *EnvelopeMonitor) Violations() []Violation {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Violation, len(m.violations))
	copy(result, m.violations)
	return result
}
