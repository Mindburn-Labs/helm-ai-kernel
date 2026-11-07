package budget

import (
	"testing"
)

// ────────────────────────────────────────────────────────────────────────
// 200 concurrent budget checks
// ────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────
// Risk enforcer with all 4 levels x 10 checks each
// ────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────
// Autonomy shrink from 100 to 0 in steps
// ────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────
// Budget reset 24 cycles
// ────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────
// Enforcement receipt for every decision
// ────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────
// Memory store with 100 tenants
// ────────────────────────────────────────────────────────────────────────

func TestStress_RiskWeightsAllDefined(t *testing.T) {
	levels := []RiskLevel{RiskLow, RiskMedium, RiskHigh, RiskCritical}
	for _, l := range levels {
		if _, ok := RiskWeights[l]; !ok {
			t.Fatalf("missing weight for %s", l)
		}
	}
}

func TestStress_RiskWeightValues(t *testing.T) {
	if RiskWeights[RiskLow] != 1.0 || RiskWeights[RiskMedium] != 2.0 || RiskWeights[RiskHigh] != 5.0 || RiskWeights[RiskCritical] != 10.0 {
		t.Fatal("risk weight values mismatch")
	}
}
