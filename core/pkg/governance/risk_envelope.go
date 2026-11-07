// Package governance — RiskEnvelope.
//
// Per HELM 2030 Spec §4.2:
//
//	Risk envelopes bound to action types plus aggregate risk accounting
//	(no threshold gaming). Each action type has a risk weight; aggregate
//	risk is tracked over sliding windows to prevent burst-then-cool exploitation.
package governance

import (
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
