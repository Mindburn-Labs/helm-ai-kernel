// quantum_posture: test-only coverage of existing signature behavior; no production cryptographic control or post-quantum assurance is added.
package crypto

import (
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func decisionSignatureV3Fixture() *contracts.DecisionRecord {
	return &contracts.DecisionRecord{
		ID:                "decision-v3",
		Verdict:           string(contracts.VerdictAllow),
		Reason:            "policy matched",
		ReasonCode:        "POLICY_MATCHED",
		PhenotypeHash:     "sha256:phenotype",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      "sha256:effect",
		SubjectID:         "agent:alice",
		Action:            "EXECUTE_TOOL",
		Resource:          "github.create_issue",
	}
}

func decisionForSigningTest(id, verdict, reason string) *contracts.DecisionRecord {
	decision := decisionSignatureV3Fixture()
	decision.ID = id
	decision.Verdict = verdict
	decision.Reason = reason
	return decision
}

func TestDecisionSignatureV3BindsAuthorizationFields(t *testing.T) {
	ed, err := NewEd25519Signer("ed-v3")
	if err != nil {
		t.Fatal(err)
	}
	pq, err := NewMLDSASigner("pq-v3")
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := NewHybridSigner("hybrid-v3")
	if err != nil {
		t.Fatal(err)
	}
	edVerifier, err := NewEd25519Verifier(ed.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	pqVerifier, err := NewMLDSAVerifier(pq.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	hybridVerifier, err := NewHybridVerifier(hybrid.Ed25519Signer().PublicKeyBytes(), hybrid.MLDSASigner().PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyRing()
	ring.AddKey(ed)

	cases := []struct {
		name   string
		sign   func(*contracts.DecisionRecord) error
		verify func(*contracts.DecisionRecord) (bool, error)
	}{
		{"ed25519 signer", ed.SignDecision, ed.VerifyDecision},
		{"ed25519 verifier", ed.SignDecision, edVerifier.VerifyDecision},
		{"ml-dsa-65 signer", pq.SignDecision, pq.VerifyDecision},
		{"ml-dsa-65 verifier", pq.SignDecision, pqVerifier.VerifyDecision},
		{"hybrid", hybrid.SignDecision, hybridVerifier.VerifyDecision},
		{"keyring", ring.SignDecision, ring.VerifyDecision},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := decisionSignatureV3Fixture()
			if err := tc.sign(decision); err != nil {
				t.Fatal(err)
			}
			if decision.SignatureVersion != contracts.DecisionRecordSignatureV3 {
				t.Fatalf("signature version = %q", decision.SignatureVersion)
			}
			if valid, err := tc.verify(decision); err != nil || !valid {
				t.Fatalf("valid decision rejected: valid=%t err=%v", valid, err)
			}

			explanationChanged := *decision
			explanationChanged.Reason = "different explanatory prose"
			if valid, err := tc.verify(&explanationChanged); err != nil || !valid {
				t.Fatalf("explanatory prose changed V3 verification: valid=%t err=%v", valid, err)
			}

			for name, mutate := range map[string]func(*contracts.DecisionRecord){
				"subject":        func(d *contracts.DecisionRecord) { d.SubjectID = "agent:bob" },
				"action":         func(d *contracts.DecisionRecord) { d.Action = "DELETE" },
				"resource":       func(d *contracts.DecisionRecord) { d.Resource = "billing.transfer" },
				"reason code":    func(d *contracts.DecisionRecord) { d.ReasonCode = "OVERRIDDEN" },
				"signature type": func(d *contracts.DecisionRecord) { d.SignatureType = "substituted:key" },
				"downgrade":      func(d *contracts.DecisionRecord) { d.SignatureVersion = contracts.DecisionRecordSignatureV2 },
			} {
				t.Run(name, func(t *testing.T) {
					tampered := *decision
					mutate(&tampered)
					valid, err := tc.verify(&tampered)
					if err == nil && valid {
						t.Fatal("tampered decision verified")
					}
				})
			}
		})
	}
}

func TestDecisionSignatureV3SurvivesJSONPersistence(t *testing.T) {
	signer, err := NewEd25519Signer("ed-v3-json")
	if err != nil {
		t.Fatal(err)
	}
	decision := decisionSignatureV3Fixture()
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	persisted, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	var restored contracts.DecisionRecord
	if err := json.Unmarshal(persisted, &restored); err != nil {
		t.Fatal(err)
	}
	if valid, err := signer.VerifyDecision(&restored); err != nil || !valid {
		t.Fatalf("persisted V3 decision rejected: valid=%t err=%v", valid, err)
	}
}

func TestDecisionSignatureV3RejectsIncompleteRecord(t *testing.T) {
	signer, err := NewEd25519Signer("ed-v3-incomplete")
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.SignDecision(&contracts.DecisionRecord{ID: "decision-incomplete", Verdict: "DENY"}); err == nil {
		t.Fatal("signed an incomplete authorization decision")
	}
}

func TestDecisionSignatureV2RemainsVerifiable(t *testing.T) {
	ed, err := NewEd25519Signer("ed-v2")
	if err != nil {
		t.Fatal(err)
	}
	pq, err := NewMLDSASigner("pq-v2")
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := NewHybridSigner("hybrid-v2")
	if err != nil {
		t.Fatal(err)
	}
	edVerifier, err := NewEd25519Verifier(ed.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	pqVerifier, err := NewMLDSAVerifier(pq.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	hybridVerifier, err := NewHybridVerifier(hybrid.Ed25519Signer().PublicKeyBytes(), hybrid.MLDSASigner().PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyRing()
	ring.AddKey(ed)

	cases := []struct {
		name          string
		sign          func([]byte) (string, error)
		verify        func(*contracts.DecisionRecord) (bool, error)
		signatureType string
	}{
		{"ed25519 signer", ed.Sign, ed.VerifyDecision, SigPrefixEd25519 + SigSeparator + "ed-v2"},
		{"ed25519 verifier", ed.Sign, edVerifier.VerifyDecision, SigPrefixEd25519 + SigSeparator + "ed-v2"},
		{"ml-dsa-65 signer", pq.Sign, pq.VerifyDecision, SigPrefixMLDSA65 + SigSeparator + "pq-v2"},
		{"ml-dsa-65 verifier", pq.Sign, pqVerifier.VerifyDecision, SigPrefixMLDSA65 + SigSeparator + "pq-v2"},
		{"hybrid verifier", hybrid.Sign, hybridVerifier.VerifyDecision, SigPrefixHybrid + SigSeparator + "hybrid-v2"},
		{"keyring", ed.Sign, ring.VerifyDecision, SigPrefixEd25519 + SigSeparator + "ed-v2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := &contracts.DecisionRecord{
				ID:                "decision-v2",
				Verdict:           string(contracts.VerdictAllow),
				Reason:            "historical prose is not part of V2",
				ReasonCode:        "POLICY_MATCHED",
				PhenotypeHash:     "sha256:phenotype",
				PolicyContentHash: "sha256:policy",
				EffectDigest:      "sha256:effect",
				SignatureType:     tc.signatureType,
				SignatureVersion:  contracts.DecisionRecordSignatureV2,
			}
			payload, err := CanonicalizeDecisionV2(decision.ID, decision.Verdict, decision.ReasonCode, decision.PhenotypeHash, decision.PolicyContentHash, decision.EffectDigest)
			if err != nil {
				t.Fatal(err)
			}
			decision.Signature, err = tc.sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := tc.verify(decision); err != nil || !valid {
				t.Fatalf("valid V2 decision rejected: valid=%t err=%v", valid, err)
			}

			tampered := *decision
			tampered.ReasonCode = "OVERRIDDEN"
			if valid, err := tc.verify(&tampered); err == nil && valid {
				t.Fatal("tampered V2 reason code verified")
			}
		})
	}
}
