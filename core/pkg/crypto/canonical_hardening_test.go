package crypto

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// TestCanonicalizeDecision_FullBinding verifies DRIFT-7:
// The canonical preimage must bind all security-relevant fields.
// Changing ANY bound field must invalidate the signature.
func TestCanonicalizeDecision_FullBinding(t *testing.T) {
	signer, err := NewEd25519Signer("test-key-1")
	if err != nil {
		t.Fatalf("signer creation failed: %v", err)
	}

	// Create a decision record with all fields populated
	d := &contracts.DecisionRecord{
		ID:                "dec-001",
		Verdict:           "PASS",
		Reason:            "All checks passed",
		PhenotypeHash:     "sha256:aaaa",
		PolicyContentHash: "sha256:bbbb",
		EffectDigest:      "sha256:cccc",
	}

	// Sign it
	if err := signer.SignDecision(d); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if d.Signature == "" {
		t.Fatal("signature should not be empty after signing")
	}

	// Verify original — must pass
	ok, err := signer.VerifyDecision(d)
	if err != nil || !ok {
		t.Fatalf("original signature should verify: ok=%v err=%v", ok, err)
	}

	// Test: mutating each bound field must invalidate the signature
	tamperTests := []struct {
		name   string
		tamper func(d *contracts.DecisionRecord)
	}{
		{"ID", func(d *contracts.DecisionRecord) { d.ID = "dec-TAMPERED" }},
		{"Verdict", func(d *contracts.DecisionRecord) { d.Verdict = "FAIL" }},
		// HELM-303 preimage V2: the attested reason field is the
		// machine-readable ReasonCode; free-text Reason left the preimage
		// deliberately (prose is prohibited from export and must not carry
		// the signed claim). See TestCanonicalizeDecisionV2_ReasonNotBound.
		{"ReasonCode", func(d *contracts.DecisionRecord) { d.ReasonCode = "TAMPERED_CODE" }},
		{"PhenotypeHash", func(d *contracts.DecisionRecord) { d.PhenotypeHash = "sha256:deadbeef" }},
		{"PolicyContentHash", func(d *contracts.DecisionRecord) { d.PolicyContentHash = "sha256:YYYY" }},
		{"EffectDigest", func(d *contracts.DecisionRecord) { d.EffectDigest = "sha256:ZZZZ" }},
	}

	for _, tt := range tamperTests {
		t.Run("tamper_"+tt.name, func(t *testing.T) {
			// Deep copy the signed record
			tampered := *d
			tt.tamper(&tampered)

			ok, err := signer.VerifyDecision(&tampered)
			if err != nil {
				t.Fatalf("unexpected error during verify: %v", err)
			}
			if ok {
				t.Fatalf("DRIFT-7 VIOLATION: signature verified after tampering %s — field is NOT bound in preimage", tt.name)
			}
		})
	}
}

// TestCanonicalizeDecision_EmptyFields verifies signing works with empty optional fields.
func TestCanonicalizeDecision_EmptyFields(t *testing.T) {
	signer, err := NewEd25519Signer("test-key-2")
	if err != nil {
		t.Fatalf("signer creation failed: %v", err)
	}

	d := &contracts.DecisionRecord{
		ID:      "dec-002",
		Verdict: "DENY",
		Reason:  "Policy violation",
		// All other fields empty
	}

	if err := signer.SignDecision(d); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	ok, err := signer.VerifyDecision(d)
	if err != nil || !ok {
		t.Fatalf("signature should verify with empty optional fields: ok=%v err=%v", ok, err)
	}
}


// TestCanonicalizeDecisionV2_ReasonNotBound pins the HELM-303 semantics
// change explicitly: mutating free-text Reason on a V2-signed record does NOT
// invalidate the signature — ReasonCode is the attested claim.
func TestCanonicalizeDecisionV2_ReasonNotBound(t *testing.T) {
	signer, err := NewEd25519Signer("drift7-v2-key")
	if err != nil {
		t.Fatal(err)
	}
	d := &contracts.DecisionRecord{ID: "dec-v2", Verdict: "DENY", Reason: "human words", ReasonCode: "POLICY_DENY"}
	if err := signer.SignDecision(d); err != nil {
		t.Fatal(err)
	}
	if d.SignatureVersion != contracts.DecisionRecordSignatureV2 {
		t.Fatalf("expected V2 signature version, got %q", d.SignatureVersion)
	}
	d.Reason = "different human words"
	ok, err := signer.VerifyDecision(d)
	if err != nil || !ok {
		t.Fatalf("Reason mutation must not invalidate a V2 signature (ok=%v err=%v)", ok, err)
	}
}
