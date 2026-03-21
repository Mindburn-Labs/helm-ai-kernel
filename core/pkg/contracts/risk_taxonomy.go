// Package contracts — Risk taxonomy.
//
// Per HELM 2030 Spec §5.1:
//
//	A unified risk-class taxonomy spans all effect types, enabling
//	consistent governance decisions across heterogeneous actuators.
package contracts

// RiskClass is the canonical risk classification.
type RiskClass string

const (
	RiskNone     RiskClass = "NONE"
	RiskLow      RiskClass = "LOW"
	RiskMedium   RiskClass = "MEDIUM"
	RiskHigh     RiskClass = "HIGH"
	RiskCritical RiskClass = "CRITICAL"
)

// RiskDomain categorizes the source of risk.
type RiskDomain string

const (
	RiskDomainSecurity    RiskDomain = "SECURITY"
	RiskDomainCompliance  RiskDomain = "COMPLIANCE"
	RiskDomainFinancial   RiskDomain = "FINANCIAL"
	RiskDomainOperational RiskDomain = "OPERATIONAL"
	RiskDomainReputation  RiskDomain = "REPUTATION"
	RiskDomainSafety      RiskDomain = "SAFETY"
)

// RiskClassification is a typed risk assessment for an effect or action.
type RiskClassification struct {
	EffectType    string     `json:"effect_type"`
	Class         RiskClass  `json:"class"`
	Domain        RiskDomain `json:"domain"`
	Score         float64    `json:"score"` // 0.0–1.0
	Reversible    bool       `json:"reversible"`
	RequiresHuman bool       `json:"requires_human_approval"`
	Justification string     `json:"justification"`
}

// RiskThreshold defines when a risk level triggers governance actions.
type RiskThreshold struct {
	Class            RiskClass `json:"class"`
	MinScore         float64   `json:"min_score"`
	RequiresApproval bool      `json:"requires_approval"`
	RequiresEscalation bool   `json:"requires_escalation"`
	AutoDeny         bool      `json:"auto_deny"`
}

// DefaultThresholds returns the canonical risk thresholds.
func DefaultThresholds() []RiskThreshold {
	return []RiskThreshold{
		{Class: RiskNone, MinScore: 0.0, RequiresApproval: false},
		{Class: RiskLow, MinScore: 0.2, RequiresApproval: false},
		{Class: RiskMedium, MinScore: 0.4, RequiresApproval: true},
		{Class: RiskHigh, MinScore: 0.7, RequiresApproval: true, RequiresEscalation: true},
		{Class: RiskCritical, MinScore: 0.9, RequiresApproval: true, RequiresEscalation: true, AutoDeny: true},
	}
}

// ClassifyRisk maps a numeric score to a RiskClass.
func ClassifyRisk(score float64) RiskClass {
	switch {
	case score >= 0.9:
		return RiskCritical
	case score >= 0.7:
		return RiskHigh
	case score >= 0.4:
		return RiskMedium
	case score >= 0.2:
		return RiskLow
	default:
		return RiskNone
	}
}
