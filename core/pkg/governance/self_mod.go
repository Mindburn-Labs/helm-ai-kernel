package governance

import (
	"context"
)

// ChangeClass defines the risk level of a self-modification.
type ChangeClass string

const (
	ChangeClassC0 ChangeClass = "C0_CONFIG"  // Trivial config change
	ChangeClassC1 ChangeClass = "C1_CONTENT" // Content update (prompts, docs)
	ChangeClassC2 ChangeClass = "C2_LOGIC"   // Logic update (code, methods)
	ChangeClassC3 ChangeClass = "C3_KERNEL"  // Core Kernel architecture change
)

type EvolutionGovernance struct{}

func NewEvolutionGovernance() *EvolutionGovernance {
	return &EvolutionGovernance{}
}

// EvaluateChange determines if a self-modification is allowed.
func (g *EvolutionGovernance) EvaluateChange(ctx context.Context, changeClass ChangeClass, regressionPassed bool) (bool, string) {
	switch changeClass {
	case ChangeClassC0, ChangeClassC1:
		// Auto-approve if regression passes
		if regressionPassed {
			return true, "APPROVED_AUTO"
		}
		return false, "REJECTED_TEST_FAILURE"

	case ChangeClassC2:
		// Requires strict Golden Trace regression
		if regressionPassed {
			return true, "APPROVED_VERIFIED"
		}
		return false, "REJECTED_VERIFICATION_FAILURE"

	case ChangeClassC3:
		// ALWAYS Block for Human Review
		return false, "BLOCKED_REQUIRES_HUMAN_APPROVAL"

	default:
		return false, "UNKNOWN_CLASS"
	}
}
