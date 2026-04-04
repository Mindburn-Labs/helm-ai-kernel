package actiongraph

// ActionRiskClass classifies the risk level of an ActionProposal or WorkItem.
type ActionRiskClass string

const (
	// RiskClassR0 is the lowest risk — fully autonomous, no visibility required.
	RiskClassR0 ActionRiskClass = "R0"
	// RiskClassR1 is low risk — autonomous with logging.
	RiskClassR1 ActionRiskClass = "R1"
	// RiskClassR2 is medium risk — requires inbox visibility.
	RiskClassR2 ActionRiskClass = "R2"
	// RiskClassR3 is high risk — requires approval ceremony before execution.
	RiskClassR3 ActionRiskClass = "R3"
)

// RiskClassToEffectClass maps an ActionRiskClass to the corresponding effect
// class string used by the effects gateway. Unknown risk classes default to E3.
func RiskClassToEffectClass(rc ActionRiskClass) string {
	switch rc {
	case RiskClassR0:
		return "E0"
	case RiskClassR1:
		return "E1"
	case RiskClassR2:
		return "E2"
	case RiskClassR3:
		return "E4"
	default:
		return "E3"
	}
}

// RequiresInboxVisibility returns true if the risk class mandates that the
// proposal be surfaced in the operator's inbox (R2 and above).
func RequiresInboxVisibility(rc ActionRiskClass) bool {
	return rc == RiskClassR2 || rc == RiskClassR3
}

// RequiresApprovalCeremony returns true if the risk class mandates an explicit
// approval ceremony before any work items may execute (R3 only).
func RequiresApprovalCeremony(rc ActionRiskClass) bool {
	return rc == RiskClassR3
}
