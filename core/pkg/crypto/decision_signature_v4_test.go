// quantum_posture: test-only coverage of existing signature behavior; no production cryptographic control or post-quantum assurance is added.
package crypto

import (
	"bytes"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// testDecisionV4Authority makes legacy unit fixtures explicit about the
// evaluated tuple they model. Production callers do not receive this default:
// they must provide or bind the real request before a V4 signature is issued.
func testDecisionV4Authority(decision *contracts.DecisionRecord) *contracts.DecisionRecord {
	if decision == nil {
		return nil
	}
	if decision.SubjectID == "" {
		decision.SubjectID = "test:subject"
	}
	if decision.Action == "" {
		decision.Action = "TEST_ACTION"
	}
	if decision.Resource == "" {
		decision.Resource = "test:resource"
	}
	return decision
}

func decisionSignatureV4Fixture() *contracts.DecisionRecord {
	return &contracts.DecisionRecord{
		ID:                "decision-v4",
		Verdict:           string(contracts.VerdictEscalate),
		Reason:            "semantic review required",
		ReasonCode:        string(contracts.ReasonSemanticThreatEscalate),
		PhenotypeHash:     "sha256:phenotype",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      "sha256:effect",
		SubjectID:         "agent:alice",
		Action:            "EXECUTE_TOOL",
		Resource:          "github.create_issue",
		ThreatScan: &contracts.ThreatScanRef{
			ScanID:       "scan-v4",
			MaxSeverity:  contracts.ThreatSeverityInfo,
			FindingCount: 1,
			TrustLevel:   contracts.InputTrustTainted,
			InputHash:    "sha256:input",
			Semantic: &contracts.SemanticThreatAssessment{
				Available:    true,
				ModelVersion: "semantic-advisory.v1",
				ModelHash:    "sha256:model",
				ThresholdBP:  7000,
				MaxBP:        7042,
				NearestClass: string(contracts.ThreatClassPromptInjection),
				Flagged:      true,
			},
		},
	}
}

func TestDecisionSignatureV4BindsAuthorityAndSemantics(t *testing.T) {
	ed, err := NewEd25519Signer("ed-v4")
	if err != nil {
		t.Fatal(err)
	}
	pq, err := NewMLDSASigner("pq-v4")
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := NewHybridSigner("hybrid-v4")
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
		{"ed25519", ed.SignDecision, ed.VerifyDecision},
		{"ml-dsa-65", pq.SignDecision, pq.VerifyDecision},
		{"hybrid", hybrid.SignDecision, hybridVerifier.VerifyDecision},
		{"keyring", ring.SignDecision, ring.VerifyDecision},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := decisionSignatureV4Fixture()
			if err := tc.sign(decision); err != nil {
				t.Fatal(err)
			}
			if decision.SignatureVersion != contracts.DecisionRecordSignatureV4 {
				t.Fatalf("signature version = %q, want %q", decision.SignatureVersion, contracts.DecisionRecordSignatureV4)
			}
			if decision.SignatureType == "" {
				t.Fatal("signature type was not set before signing")
			}
			if valid, err := tc.verify(decision); err != nil || !valid {
				t.Fatalf("valid V4 decision rejected: valid=%t err=%v", valid, err)
			}

			for name, mutate := range map[string]func(*contracts.DecisionRecord){
				"subject":        func(d *contracts.DecisionRecord) { d.SubjectID = "agent:bob" },
				"action":         func(d *contracts.DecisionRecord) { d.Action = "DELETE" },
				"resource":       func(d *contracts.DecisionRecord) { d.Resource = "billing.transfer" },
				"signature type": func(d *contracts.DecisionRecord) { d.SignatureType = "substituted:key" },
				"reason":         func(d *contracts.DecisionRecord) { d.Reason = "operator override" },
				"threat scan": func(d *contracts.DecisionRecord) {
					threat := *d.ThreatScan
					semantic := *threat.Semantic
					semantic.MaxBP--
					threat.Semantic = &semantic
					d.ThreatScan = &threat
				},
			} {
				t.Run(name, func(t *testing.T) {
					tampered := *decision
					mutate(&tampered)
					if valid, err := tc.verify(&tampered); err == nil && valid {
						t.Fatal("tampered V4 decision verified")
					}
				})
			}
		})
	}
}

func TestDecisionSignatureV4RejectsIncompleteAuthority(t *testing.T) {
	signer, err := NewEd25519Signer("ed-v4-incomplete")
	if err != nil {
		t.Fatal(err)
	}
	decision := &contracts.DecisionRecord{ID: "decision-incomplete", Verdict: string(contracts.VerdictDeny)}
	if err := signer.SignDecision(decision); err == nil {
		t.Fatal("signed a decision without its evaluated authority tuple")
	}
	if decision.SignatureVersion != "" || decision.SignatureType != "" {
		t.Fatalf("failed signing mutated decision metadata: %+v", decision)
	}
}

func TestCanonicalizeDecisionV4MatchesJCS(t *testing.T) {
	decision := decisionSignatureV4Fixture()
	decision.SignatureType = SigPrefixEd25519 + SigSeparator + "canonical-v4"

	got, err := CanonicalizeDecisionV4(decision)
	if err != nil {
		t.Fatal(err)
	}
	threatScanHash, err := decisionThreatScanHash(decision.ThreatScan)
	if err != nil {
		t.Fatal(err)
	}
	want, err := canonicalize.JCS(decisionV4SigningEnvelope{
		SignatureVersion:  contracts.DecisionRecordSignatureV4,
		ID:                decision.ID,
		Verdict:           decision.Verdict,
		ReasonCode:        decision.ReasonCode,
		ReasonHash:        HashReason(decision.Reason),
		PhenotypeHash:     decision.PhenotypeHash,
		PolicyContentHash: decision.PolicyContentHash,
		EffectDigest:      decision.EffectDigest,
		ThreatScanHash:    threatScanHash,
		SubjectID:         decision.SubjectID,
		Action:            decision.Action,
		Resource:          decision.Resource,
		SignatureType:     decision.SignatureType,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("V4 canonical payload differs from JCS:\n got: %s\nwant: %s", got, want)
	}
}

func TestDecisionSignatureV4PreservesV2AndV3Verification(t *testing.T) {
	signer, err := NewEd25519Signer("ed-legacy")
	if err != nil {
		t.Fatal(err)
	}

	v2 := &contracts.DecisionRecord{
		ID:                "decision-v2",
		Verdict:           string(contracts.VerdictAllow),
		Reason:            "historical decision explanation",
		ReasonCode:        "",
		PhenotypeHash:     "sha256:phenotype",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      "sha256:effect",
		SignatureType:     SigPrefixEd25519 + SigSeparator + "ed-legacy",
		SignatureVersion:  contracts.DecisionRecordSignatureV2,
	}
	payload, err := CanonicalizeDecisionV2(v2.ID, v2.Verdict, v2.Reason, v2.ReasonCode, v2.PhenotypeHash, v2.PolicyContentHash, v2.EffectDigest)
	if err != nil {
		t.Fatal(err)
	}
	v2.Signature, err = signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := signer.VerifyDecision(v2); err != nil || !valid {
		t.Fatalf("V2 verification changed: valid=%t err=%v", valid, err)
	}

	v3 := decisionSignatureV4Fixture()
	v3.SignatureVersion = contracts.DecisionRecordSignatureV3
	v3.SignatureType = SigPrefixEd25519 + SigSeparator + "ed-legacy"
	payload, err = CanonicalizeDecisionV3(v3.ID, v3.Verdict, v3.Reason, v3.ReasonCode, v3.PhenotypeHash, v3.PolicyContentHash, v3.EffectDigest, v3.ThreatScan)
	if err != nil {
		t.Fatal(err)
	}
	v3.Signature, err = signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := signer.VerifyDecision(v3); err != nil || !valid {
		t.Fatalf("V3 verification changed: valid=%t err=%v", valid, err)
	}

	v3.Reason = "rewritten explanation"
	if valid, err := signer.VerifyDecision(v3); err == nil && valid {
		t.Fatal("V3 reason digest was no longer verified")
	}

	v3.SignatureVersion = "decision_record.v999"
	if _, err := DecisionVerifyPayload(v3); err == nil {
		t.Fatal("unknown decision signature version was accepted")
	}
}
