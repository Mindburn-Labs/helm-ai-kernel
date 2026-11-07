package budget

import (
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
