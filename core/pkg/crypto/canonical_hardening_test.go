// quantum_posture: test-only coverage of existing signature behavior; no production cryptographic control or post-quantum assurance is added.
package crypto

import (
	"bytes"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
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
		ReasonCode:        "POLICY_MATCHED",
		PhenotypeHash:     "sha256:aaaa",
		PolicyContentHash: "sha256:bbbb",
		EffectDigest:      "sha256:cccc",
		SubjectID:         "agent:alice",
		Action:            "EXECUTE_TOOL",
		Resource:          "tool:publish",
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
		// V3 retains the V2 rule: ReasonCode is the signed claim and free-text
		// Reason remains explanatory only.
		{"ReasonCode", func(d *contracts.DecisionRecord) { d.ReasonCode = "TAMPERED_CODE" }},
		{"PhenotypeHash", func(d *contracts.DecisionRecord) { d.PhenotypeHash = "sha256:deadbeef" }},
		{"PolicyContentHash", func(d *contracts.DecisionRecord) { d.PolicyContentHash = "sha256:YYYY" }},
		{"EffectDigest", func(d *contracts.DecisionRecord) { d.EffectDigest = "sha256:ZZZZ" }},
		{"SubjectID", func(d *contracts.DecisionRecord) { d.SubjectID = "agent:bob" }},
		{"Action", func(d *contracts.DecisionRecord) { d.Action = "DELETE" }},
		{"Resource", func(d *contracts.DecisionRecord) { d.Resource = "tool:delete" }},
		{"SignatureType", func(d *contracts.DecisionRecord) { d.SignatureType = "ed25519:other" }},
		{"SignatureVersion", func(d *contracts.DecisionRecord) { d.SignatureVersion = contracts.DecisionRecordSignatureV2 }},
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
		ID:        "dec-002",
		Verdict:   "DENY",
		Reason:    "Policy violation",
		SubjectID: "agent:alice",
		Action:    "EXECUTE_TOOL",
		Resource:  "tool:read",
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

func TestCanonicalizeDecisionV3MatchesJCS(t *testing.T) {
	d := &contracts.DecisionRecord{
		ID:                "dec-\x01-\"quoted\"",
		Verdict:           "ALLOW",
		ReasonCode:        "POLICY_MATCHED",
		PhenotypeHash:     "sha256:phenotype",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      "sha256:effect",
		SubjectID:         "agent:alice",
		Action:            "EXECUTE_TOOL",
		Resource:          "tool:read",
		SignatureType:     "ed25519:key\\one",
	}
	got, err := CanonicalizeDecisionV3(d)
	if err != nil {
		t.Fatal(err)
	}
	want, err := canonicalize.JCS(map[string]string{
		"action":              d.Action,
		"effect_digest":       d.EffectDigest,
		"id":                  d.ID,
		"phenotype_hash":      d.PhenotypeHash,
		"policy_content_hash": d.PolicyContentHash,
		"reason_code":         d.ReasonCode,
		"resource":            d.Resource,
		"signature_type":      d.SignatureType,
		"signature_version":   contracts.DecisionRecordSignatureV3,
		"subject_id":          d.SubjectID,
		"verdict":             d.Verdict,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("V3 payload differs from JCS\n got: %s\nwant: %s", got, want)
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
	d := &contracts.DecisionRecord{
		ID:               "dec-v2",
		Verdict:          "DENY",
		Reason:           "human words",
		ReasonCode:       "POLICY_DENY",
		SignatureVersion: contracts.DecisionRecordSignatureV2,
		SignatureType:    SigPrefixEd25519 + SigSeparator + "drift7-v2-key",
	}
	payload, err := CanonicalizeDecisionV2(d.ID, d.Verdict, d.ReasonCode, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	if err != nil {
		t.Fatal(err)
	}
	if d.Signature, err = signer.Sign(payload); err != nil {
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

func TestDecisionSemanticHashIgnoresUnsignedPolicyDecisionHash(t *testing.T) {
	signer, err := NewEd25519Signer("decision-semantic-hash")
	if err != nil {
		t.Fatal(err)
	}
	decision := &contracts.DecisionRecord{
		ID:                 "dec-semantic",
		Verdict:            string(contracts.VerdictAllow),
		ReasonCode:         "POLICY_ALLOW",
		PhenotypeHash:      "sha256:phenotype",
		PolicyContentHash:  "sha256:policy",
		EffectDigest:       "sha256:effect",
		SubjectID:          "agent:alice",
		Action:             "EXECUTE_TOOL",
		Resource:           "tool:read",
		PolicyDecisionHash: "sha256:trusted-source",
	}
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	decision.PolicyDecisionHash = "sha256:attacker-chosen"
	ok, err := signer.VerifyDecision(decision)
	if err != nil || !ok {
		t.Fatalf("policy_decision_hash is outside the current signed payload: ok=%v err=%v", ok, err)
	}

	got, err := DecisionSemanticHash(decision)
	if err != nil {
		t.Fatal(err)
	}
	want, err := DecisionContentHash(decision)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("semantic decision hash = %q, want signed payload hash %q", got, want)
	}
	if got == decision.PolicyDecisionHash {
		t.Fatalf("semantic decision hash trusted unsigned policy_decision_hash %q", got)
	}
}
