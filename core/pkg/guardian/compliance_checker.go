package guardian

import "context"

// ComplianceChecker is the interface that the Guardian uses to evaluate
// compliance obligations before proceeding with governance decisions.
// This interface decouples the Guardian from the enforcement engine,
// allowing different compliance backends to be plugged in.
type ComplianceChecker interface {
	// CheckCompliance evaluates whether the given action is compliant
	// with all active obligations for the entity. Returns a result
	// indicating PERMIT or DENY with obligation-level detail.
	CheckCompliance(ctx context.Context, entityID, action string, context map[string]interface{}) (*ComplianceCheckResult, error)
}

// ComplianceCheckResult is the outcome of a compliance pre-check.
type ComplianceCheckResult struct {
	// Compliant is true if all obligations are satisfied for this action.
	Compliant bool `json:"compliant"`

	// Reason is a human-readable explanation (populated on non-compliance).
	Reason string `json:"reason,omitempty"`

	// ObligationsChecked is the number of obligations evaluated.
	ObligationsChecked int `json:"obligations_checked"`

	// ViolatedObligations lists the IDs of obligations that were violated.
	ViolatedObligations []string `json:"violated_obligations,omitempty"`
}
