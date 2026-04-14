package governance

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

func TestPolicyEngine_Evaluate(t *testing.T) {
	eng, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test Pass
	allowed, err := eng.EvaluateInline("risk_score < 80", map[string]interface{}{
		"risk_score": 50,
		"action":     "deploy",
	})
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}
	if !allowed {
		t.Error("Expected allow")
	}

	// Test Fail
	allowed, err = eng.EvaluateInline("risk_score < 80", map[string]interface{}{
		"risk_score": 90,
		"action":     "deploy",
	})
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}
	if allowed {
		t.Error("Expected deny")
	}
}

func TestGuardian_Authorize(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("guardian-key")
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}
	eng, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	guardian := NewGuardian(signer, eng)

	// Test Authorization
	dec, err := guardian.Authorize("deploy", 20)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	if dec.Verdict != "ALLOW" {
		t.Errorf("Expected ALLOW, got %s", dec.Verdict)
	}
	if dec.Signature == "" {
		t.Error("Expected signature on decision")
	}

	// Verify signature
	valid, err := signer.VerifyDecision(dec)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !valid {
		t.Error("Guardian produced invalid signature")
	}

	// Test Rejection
	dec, err = guardian.Authorize("nuke", 100)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if dec.Verdict != "DENY" {
		t.Errorf("Expected DENY, got %s", dec.Verdict)
	}
}
