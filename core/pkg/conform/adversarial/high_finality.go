// Package adversarial provides conformance-level adversarial test suites
// per §8.1 of the HELM Conformance Standard.
//
// # High-Finality Actions
//
// A high-finality action is any effect classified as E4 (irreversible) or
// E5 (catastrophic). These actions MUST have a corresponding approval_action
// receipt linked via decision_id before execution. ADV-10 enforces this
// invariant.
//
// The HighFinalityClasses and IsHighFinality function provide the canonical
// definition used by both runtime enforcement and conformance verification.
package adversarial

// HighFinalityClasses defines which effect classes are high-finality.
// E4 = irreversible, E5 = catastrophic.
var HighFinalityClasses = map[string]bool{
	"E4": true,
	"E5": true,
}

// IsHighFinalityAction returns true if the given action requires HITL approval.
func IsHighFinalityAction(effectClass, actionType string) bool {
	return isHighFinality(effectClass, actionType)
}
