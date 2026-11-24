package budget

import "testing"

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
