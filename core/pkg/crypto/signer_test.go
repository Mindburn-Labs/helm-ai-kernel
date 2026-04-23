package crypto

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func TestSigner_Integrity(t *testing.T) {
	signer, err := NewEd25519Signer("key-1")
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	decision := &contracts.DecisionRecord{
		ID:      "dec-123",
		Verdict: "PASS",
		Reason:  "Looks good",
	}

	// 1. Sign
	if err := signer.SignDecision(decision); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if decision.Signature == "" {
		t.Error("Signature empty")
	}

	// 2. Verify Valid
	valid, err := signer.VerifyDecision(decision)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("Valid decision rejected")
	}

	// 3. Verify Tampered
	decision.Reason = "I changed this"
	valid, _ = signer.VerifyDecision(decision)
	if valid {
		t.Error("Tampered decision accepted")
	}
}
