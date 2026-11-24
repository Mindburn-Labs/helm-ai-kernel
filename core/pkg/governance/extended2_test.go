package governance

import "testing"

func TestExt2_CanaryDefaultConfig(t *testing.T) {
	if DefaultCanary.Steps != 3 || DefaultCanary.StepDurationSec != 300 {
		t.Fatalf("unexpected default canary: steps=%d dur=%d", DefaultCanary.Steps, DefaultCanary.StepDurationSec)
	}
}

func TestExt2_CanaryFastConfig(t *testing.T) {
	if FastCanary.Steps != 1 || FastCanary.StepDurationSec != 30 {
		t.Fatalf("unexpected fast canary: steps=%d dur=%d", FastCanary.Steps, FastCanary.StepDurationSec)
	}
}
