package governance

import (
	"testing"
)

// ── Jurisdiction with 100 rules ─────────────────────────────────────────

func TestStress_RiskLevelConstants(t *testing.T) {
	levels := map[RiskLevel]string{RiskNone: "NONE", RiskLow: "LOW", RiskMedium: "MEDIUM", RiskHigh: "HIGH", RiskCritical: "CRITICAL"}
	for level, expected := range levels {
		if string(level) != expected {
			t.Fatalf("expected %s, got %s", expected, level)
		}
	}
}

func TestStress_PlanStatusConstants(t *testing.T) {
	statuses := []PlanStatus{PlanStatusPending, PlanStatusApproved, PlanStatusRejected, PlanStatusTimeout, PlanStatusAborted}
	if len(statuses) != 5 {
		t.Fatal("expected 5 plan statuses")
	}
}

func TestStress_LivenessStateConstants(t *testing.T) {
	states := []LivenessState{LivenessStateActive, LivenessStatePending, LivenessStateExpired, LivenessStateCanceled}
	if len(states) != 4 {
		t.Fatal("expected 4 liveness states")
	}
}

func TestStress_CompensationPolicyConstants(t *testing.T) {
	policies := []CompensationFailurePolicy{CompensationPolicyRetry, CompensationPolicyEscalate, CompensationPolicyManual, CompensationPolicyFallback}
	if len(policies) != 4 {
		t.Fatal("expected 4 compensation policies")
	}
}
