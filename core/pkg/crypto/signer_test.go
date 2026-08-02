package crypto

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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

	// HELM-303 (preimage V2): ReasonCode is attested, and free-text Reason
	// stays attested as reason_hash — rewriting the emitted explanation must
	// still break the signature.
	decision.Reason = "I changed this"
	valid, err = signer.VerifyDecision(decision)
	if err != nil {
		t.Fatalf("VerifyDecision after Reason mutation: %v", err)
	}
	if valid {
		t.Error("Reason is bound via reason_hash; mutating it must invalidate the V2 signature")
	}
	decision.ReasonCode = "TAMPERED_CODE"
	valid, _ = signer.VerifyDecision(decision)
	if valid {
		t.Error("Tampered ReasonCode accepted")
	}
}
