package crypto

import (
	"bytes"
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

// TestCanonicalizeDecisionV2_ReasonBoundByHash pins the HELM-303 semantics:
// V2 promotes ReasonCode into the preimage without dropping free-text Reason,
// which stays attested as reason_hash. Binding the code alone would have been a
// regression — ReasonCode is empty by contract on ALLOW, so the emitted
// explanation would have been freely rewritable past verification.
func TestCanonicalizeDecisionV2_ReasonBoundByHash(t *testing.T) {
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
	if err != nil {
		t.Fatalf("verify after Reason mutation: %v", err)
	}
	if ok {
		t.Fatal("Reason mutation must invalidate a V2 signature: it is bound as reason_hash")
	}

	// The prose itself must not appear in the preimage — only its digest.
	d.Reason = "human words"
	payload, err := CanonicalizeDecisionV2(d)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("human words")) {
		t.Fatalf("free-text Reason leaked into the signed preimage: %s", payload)
	}
}

// An ALLOW decision carries no ReasonCode by contract. Its explanation must
// still be attested, otherwise V2 would authenticate nothing about why the
// action was permitted.
func TestCanonicalizeDecisionV2_AllowReasonStillBound(t *testing.T) {
	signer, err := NewEd25519Signer("v2-allow-key")
	if err != nil {
		t.Fatal(err)
	}
	d := &contracts.DecisionRecord{ID: "dec-allow", Verdict: string(contracts.VerdictAllow), Reason: "within budget"}
	if err := signer.SignDecision(d); err != nil {
		t.Fatal(err)
	}
	d.Reason = "policy explicitly permitted this"
	ok, err := signer.VerifyDecision(d)
	if err != nil {
		t.Fatalf("verify after Reason mutation: %v", err)
	}
	if ok {
		t.Fatal("an ALLOW decision's explanation is unauthenticated — V2 attests nothing on the allow path")
	}
}
