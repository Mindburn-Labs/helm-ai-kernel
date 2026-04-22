package budget

import (
	"fmt"
	"sync"
	"time"
)

// RiskLevel categorizes the risk multiplier for an action.
type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// RiskWeights maps risk levels to cost multipliers.
var RiskWeights = map[RiskLevel]float64{
	RiskLow:      1.0,
	RiskMedium:   2.0,
	RiskHigh:     5.0,
	RiskCritical: 10.0,
}

// RiskBudget extends the base budget with risk-weighted, blast-radius, and compute limits.
type RiskBudget struct {
	TenantID          string  `json:"tenant_id"`
	ComputeCapMillis  int64   `json:"compute_cap_millis"` // Max compute time in ms
	ComputeUsedMillis int64   `json:"compute_used_millis"`
	BlastRadiusCap    int     `json:"blast_radius_cap"` // Max affected resources
	BlastRadiusUsed   int     `json:"blast_radius_used"`
	RiskScoreCap      float64 `json:"risk_score_cap"` // Aggregate risk score
	RiskScoreUsed     float64 `json:"risk_score_used"`
	AutonomyLevel     int     `json:"autonomy_level"`    // 0-100, shrinks under uncertainty
	UncertaintyScore  float64 `json:"uncertainty_score"` // 0.0-1.0
}

// RiskDecision is the result of a risk budget check.
type RiskDecision struct {
	Allowed          bool    `json:"allowed"`
	Reason           string  `json:"reason"`
	RiskCost         float64 `json:"risk_cost"`
	AutonomyShrunk   bool    `json:"autonomy_shrunk"`
	NewAutonomyLevel int     `json:"new_autonomy_level,omitempty"`
}

// RiskEnforcer manages risk-weighted budgets.
type RiskEnforcer struct {
	mu      sync.Mutex
	budgets map[string]*RiskBudget
	clock   func() time.Time
}

// NewRiskEnforcer creates a new risk budget enforcer.
func NewRiskEnforcer() *RiskEnforcer {
	return &RiskEnforcer{
		budgets: make(map[string]*RiskBudget),
		clock:   time.Now,
	}
}

// WithClock overrides clock for testing.
func (e *RiskEnforcer) WithClock(clock func() time.Time) *RiskEnforcer {
	e.clock = clock
	return e
}

// SetBudget sets the risk budget for a tenant.
func (e *RiskEnforcer) SetBudget(budget *RiskBudget) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.budgets[budget.TenantID] = budget
}

// GetBudget retrieves the current risk budget.
func (e *RiskEnforcer) GetBudget(tenantID string) (*RiskBudget, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	b, ok := e.budgets[tenantID]
	if !ok {
		return nil, fmt.Errorf("no risk budget for tenant %q", tenantID)
	}
	return b, nil
}

// CheckRisk evaluates if an action's risk is within budget.
func (e *RiskEnforcer) CheckRisk(tenantID string, riskLevel RiskLevel, baseCost float64, blastRadius int) *RiskDecision {
	e.mu.Lock()
	defer e.mu.Unlock()

	b, ok := e.budgets[tenantID]
	if !ok {
		// Fail-closed: no budget = denied
		return &RiskDecision{
			Allowed: false,
			Reason:  "no risk budget configured",
		}
	}

	weight := RiskWeights[riskLevel]
	riskCost := baseCost * weight

	// Check aggregate risk score
	if b.RiskScoreUsed+riskCost > b.RiskScoreCap {
		return &RiskDecision{
			Allowed:  false,
			Reason:   fmt.Sprintf("risk score %.1f would exceed cap %.1f", b.RiskScoreUsed+riskCost, b.RiskScoreCap),
			RiskCost: riskCost,
		}
	}

	// Check blast radius
	if b.BlastRadiusUsed+blastRadius > b.BlastRadiusCap {
		return &RiskDecision{
			Allowed:  false,
			Reason:   fmt.Sprintf("blast radius %d would exceed cap %d", b.BlastRadiusUsed+blastRadius, b.BlastRadiusCap),
			RiskCost: riskCost,
		}
	}

	// Reserve
	b.RiskScoreUsed += riskCost
	b.BlastRadiusUsed += blastRadius

	return &RiskDecision{
		Allowed:  true,
		Reason:   "within risk budget",
		RiskCost: riskCost,
	}
}

// CheckCompute checks if a compute request is within budget.
func (e *RiskEnforcer) CheckCompute(tenantID string, durationMillis int64) *RiskDecision {
	e.mu.Lock()
	defer e.mu.Unlock()

	b, ok := e.budgets[tenantID]
	if !ok {
		return &RiskDecision{
			Allowed: false,
			Reason:  "no risk budget configured",
		}
	}

	if b.ComputeUsedMillis+durationMillis > b.ComputeCapMillis {
		return &RiskDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("compute %dms would exceed cap %dms", b.ComputeUsedMillis+durationMillis, b.ComputeCapMillis),
		}
	}

	b.ComputeUsedMillis += durationMillis
	return &RiskDecision{
		Allowed: true,
		Reason:  "within compute budget",
	}
}

// ShrinkAutonomy reduces autonomy level based on uncertainty.
// When uncertainty rises above a threshold, the system automatically
// restricts what actions can be taken without human approval.
func (e *RiskEnforcer) ShrinkAutonomy(tenantID string, uncertaintyDelta float64) *RiskDecision {
	e.mu.Lock()
	defer e.mu.Unlock()

	b, ok := e.budgets[tenantID]
	if !ok {
		return &RiskDecision{
			Allowed: false,
			Reason:  "no risk budget configured",
		}
	}

	b.UncertaintyScore += uncertaintyDelta
	if b.UncertaintyScore > 1.0 {
		b.UncertaintyScore = 1.0
	}
	if b.UncertaintyScore < 0.0 {
		b.UncertaintyScore = 0.0
	}

	// Autonomy shrinks proportionally to uncertainty
	// At 0 uncertainty → 100 autonomy; at 1.0 uncertainty → 0 autonomy
	oldLevel := b.AutonomyLevel
	b.AutonomyLevel = int(100.0 * (1.0 - b.UncertaintyScore))

	shrunk := b.AutonomyLevel < oldLevel
	return &RiskDecision{
		Allowed:          true,
		Reason:           fmt.Sprintf("autonomy adjusted: %d → %d (uncertainty: %.2f)", oldLevel, b.AutonomyLevel, b.UncertaintyScore),
		AutonomyShrunk:   shrunk,
		NewAutonomyLevel: b.AutonomyLevel,
	}
}

// IsAutonomousAllowed checks if the current autonomy level permits autonomous actions
// at the given risk level.
func (e *RiskEnforcer) IsAutonomousAllowed(tenantID string, riskLevel RiskLevel) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	b, ok := e.budgets[tenantID]
	if !ok {
		return false // Fail-closed
	}

	// Autonomy thresholds per risk level
	thresholds := map[RiskLevel]int{
		RiskLow:      10,  // Allowed above autonomy 10
		RiskMedium:   40,  // Allowed above autonomy 40
		RiskHigh:     70,  // Allowed above autonomy 70
		RiskCritical: 100, // Never autonomous (requires 100+, impossible)
	}

	threshold := thresholds[riskLevel]
	return b.AutonomyLevel >= threshold
}
