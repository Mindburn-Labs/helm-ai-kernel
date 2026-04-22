package scenarios

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel"
)

// Scenario 4: Environment Recreate / Kiro-Style
//
// Threat: Agent operates in a recreated/tampered environment where the
// execution context has been changed underneath it.
// Expected: DENY with CONTEXT_MISMATCH.
func TestEnvRecreate_ContextMismatchDetected(t *testing.T) {
	cg := kernel.NewContextGuardWithFingerprint("original-boot-fp-sha256-abcdef")

	// Validate with the original fingerprint — should pass
	if err := cg.Validate("original-boot-fp-sha256-abcdef"); err != nil {
		t.Fatalf("original fingerprint should match: %v", err)
	}

	// Environment is recreated — fingerprint changes
	err := cg.Validate("recreated-env-fp-sha256-999999")
	if err == nil {
		t.Fatal("recreated environment should trigger CONTEXT_MISMATCH")
	}

	mismatch, ok := err.(*kernel.ContextMismatchError)
	if !ok {
		t.Fatalf("error type = %T, want *ContextMismatchError", err)
	}
	if mismatch.BootFingerprint != "original-boot-fp-sha256-abcdef" {
		t.Errorf("boot fp = %s, unexpected", mismatch.BootFingerprint)
	}
	if mismatch.CurrentFingerprint != "recreated-env-fp-sha256-999999" {
		t.Errorf("current fp = %s, unexpected", mismatch.CurrentFingerprint)
	}
}

func TestEnvRecreate_EffectClassification(t *testing.T) {
	et := contracts.LookupEffectType(contracts.EffectTypeEnvRecreate)
	if et == nil {
		t.Fatal("ENV_RECREATE not found in catalog")
	}
	if et.Classification.BlastRadius != "system_wide" {
		t.Errorf("blast radius = %s, want system_wide", et.Classification.BlastRadius)
	}
	if et.Classification.Reversibility != "compensatable" {
		t.Errorf("reversibility = %s, want compensatable", et.Classification.Reversibility)
	}

	rc := contracts.EffectRiskClass(contracts.EffectTypeEnvRecreate)
	if rc != "E3" {
		t.Errorf("risk class = %s, want E3", rc)
	}
}

func TestEnvRecreate_RiskSummaryContextMismatch(t *testing.T) {
	rs := contracts.ComputeRiskSummary(contracts.EffectTypeEnvRecreate, contracts.WithContextMismatch())
	if rs.OverallRisk != "CRITICAL" {
		t.Errorf("env recreate + context mismatch = %s, want CRITICAL", rs.OverallRisk)
	}
	if rs.ContextMatch {
		t.Error("ContextMatch should be false")
	}
}
