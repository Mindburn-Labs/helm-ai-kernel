// Package governance — RiskEnvelope.
//
// Per HELM 2030 Spec §4.2:
//
//	Risk envelopes bound to action types plus aggregate risk accounting
//	(no threshold gaming). Each action type has a risk weight; aggregate
//	risk is tracked over sliding windows to prevent burst-then-cool exploitation.
package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// RiskLevel categorizes risk.
type RiskLevel string

const (
	RiskNone     RiskLevel = "NONE"
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// RiskEnvelope binds a risk limit to a specific action type.
type RiskEnvelope struct {
	EnvelopeID  string    `json:"envelope_id"`
	ActionType  string    `json:"action_type"`
	MaxRisk     float64   `json:"max_risk"` // per-action risk ceiling
	Weight      float64   `json:"weight"`   // risk weight for aggregate
	Level       RiskLevel `json:"level"`
	Description string    `json:"description"`
}

// RiskEvent records a risk-consuming event.
type RiskEvent struct {
	EventID    string    `json:"event_id"`
	ActionType string    `json:"action_type"`
	RiskCost   float64   `json:"risk_cost"`
	Timestamp  time.Time `json:"timestamp"`
}

// AggregateRiskAccounting tracks risk across sliding windows to prevent gaming.
type AggregateRiskAccounting struct {
	mu             sync.Mutex
	envelopes      map[string]*RiskEnvelope // actionType → envelope
	events         []RiskEvent
	windowDuration time.Duration
	maxAggregate   float64
	seq            int64
	clock          func() time.Time
}

// NewAggregateRiskAccounting creates a new risk accounting system.
func NewAggregateRiskAccounting(windowDuration time.Duration, maxAggregate float64) *AggregateRiskAccounting {
	return &AggregateRiskAccounting{
		envelopes:      make(map[string]*RiskEnvelope),
		events:         make([]RiskEvent, 0),
		windowDuration: windowDuration,
		maxAggregate:   maxAggregate,
		clock:          time.Now,
	}
}

// WithClock overrides clock for testing.
func (a *AggregateRiskAccounting) WithClock(clock func() time.Time) *AggregateRiskAccounting {
	a.clock = clock
	return a
}

// RegisterEnvelope adds a risk envelope for an action type.
func (a *AggregateRiskAccounting) RegisterEnvelope(env *RiskEnvelope) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.envelopes[env.ActionType] = env
}

// CheckAndRecord checks if an action is within risk limits and records it.
// Returns error if risk would be exceeded (fail-closed).
func (a *AggregateRiskAccounting) CheckAndRecord(actionType string, riskCost float64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.clock()

	// Check per-action envelope
	env, ok := a.envelopes[actionType]
	if ok && riskCost > env.MaxRisk {
		return fmt.Errorf("action %q risk %.2f exceeds envelope max %.2f", actionType, riskCost, env.MaxRisk)
	}

	// Calculate weighted cost
	weightedCost := riskCost
	if ok {
		weightedCost = riskCost * env.Weight
	}

	// Calculate aggregate in window
	windowStart := now.Add(-a.windowDuration)
	var aggregate float64
	for _, e := range a.events {
		if e.Timestamp.After(windowStart) {
			w := 1.0
			if env2, ok2 := a.envelopes[e.ActionType]; ok2 {
				w = env2.Weight
			}
			aggregate += e.RiskCost * w
		}
	}

	// Check aggregate (anti-gaming: can't burst then cool down)
	if aggregate+weightedCost > a.maxAggregate {
		return fmt.Errorf("aggregate risk %.2f + %.2f exceeds window max %.2f", aggregate, weightedCost, a.maxAggregate)
	}

	// Record event
	a.seq++
	a.events = append(a.events, RiskEvent{
		EventID:    fmt.Sprintf("re-%d", a.seq),
		ActionType: actionType,
		RiskCost:   riskCost,
		Timestamp:  now,
	})

	return nil
}

// CurrentAggregate returns the current aggregate risk in the window.
func (a *AggregateRiskAccounting) CurrentAggregate() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.clock()
	windowStart := now.Add(-a.windowDuration)
	var aggregate float64
	for _, e := range a.events {
		if e.Timestamp.After(windowStart) {
			w := 1.0
			if env, ok := a.envelopes[e.ActionType]; ok {
				w = env.Weight
			}
			aggregate += e.RiskCost * w
		}
	}
	return aggregate
}

// Snapshot returns a hash of the current risk state.
func (a *AggregateRiskAccounting) Snapshot() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	hashInput := fmt.Sprintf("risk:%d:%.2f", len(a.events), a.maxAggregate)
	h := sha256.Sum256([]byte(hashInput))
	return "sha256:" + hex.EncodeToString(h[:])
}
