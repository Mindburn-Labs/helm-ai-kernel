package contracts

// RiskSummary is the machine-readable risk assessment attached to every
// enforcement decision. Operators and downstream systems parse this to
// understand the risk profile of a proposed action without interpreting
// policy details.
type RiskSummary struct {
	EffectTypeID     string `json:"effect_type_id"`
	EffectClass      string `json:"effect_class"` // E0-E4
	OverallRisk      string `json:"overall_risk"` // LOW, MEDIUM, HIGH, CRITICAL
	ApprovalRequired bool   `json:"approval_required"`
	BudgetImpact     bool   `json:"budget_impact"`
	EgressRisk       bool   `json:"egress_risk"`
	IdentityRisk     bool   `json:"identity_risk"`
	ContextMatch     bool   `json:"context_match"`
	Frozen           bool   `json:"frozen"`
}

// ComputeRiskSummary generates a RiskSummary from effect type and enforcement state.
func ComputeRiskSummary(effectTypeID string, opts ...RiskOption) *RiskSummary {
	rs := &RiskSummary{
		EffectTypeID: effectTypeID,
		EffectClass:  EffectRiskClass(effectTypeID),
		ContextMatch: true, // default: context is valid
	}

	for _, opt := range opts {
		opt(rs)
	}

	// Derive overall risk from effect class + flags
	rs.OverallRisk = deriveOverallRisk(rs)

	// E3/E4 always require approval
	if rs.EffectClass == "E4" || rs.EffectClass == "E3" {
		rs.ApprovalRequired = true
	}

	return rs
}

// RiskOption is a functional option for configuring risk assessment.
type RiskOption func(*RiskSummary)

// WithBudgetImpact marks the action as having budget implications.
func WithBudgetImpact() RiskOption { return func(rs *RiskSummary) { rs.BudgetImpact = true } }

// WithEgressRisk marks the action as involving data egress.
func WithEgressRisk() RiskOption { return func(rs *RiskSummary) { rs.EgressRisk = true } }

// WithIdentityRisk marks the action as having identity concerns.
func WithIdentityRisk() RiskOption { return func(rs *RiskSummary) { rs.IdentityRisk = true } }

// WithContextMismatch marks a context fingerprint mismatch.
func WithContextMismatch() RiskOption { return func(rs *RiskSummary) { rs.ContextMatch = false } }

// WithFrozen marks the system as being in freeze state.
func WithFrozen() RiskOption { return func(rs *RiskSummary) { rs.Frozen = true } }

func deriveOverallRisk(rs *RiskSummary) string {
	if rs.Frozen || !rs.ContextMatch {
		return "CRITICAL"
	}
	switch rs.EffectClass {
	case "E4":
		return "CRITICAL"
	case "E3":
		return "HIGH"
	case "E2":
		if rs.BudgetImpact || rs.EgressRisk {
			return "HIGH"
		}
		return "MEDIUM"
	case "E1":
		return "LOW"
	case "E0":
		return "LOW"
	default:
		return "HIGH" // fail-closed: unknown class → high risk
	}
}
