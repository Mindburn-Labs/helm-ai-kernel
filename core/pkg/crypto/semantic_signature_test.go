package crypto

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestDecisionV3ThreatEvidenceIsBound(t *testing.T) {
	signer, err := NewEd25519Signer("semantic-signature-test")
	if err != nil {
		t.Fatal(err)
	}
	decision := &contracts.DecisionRecord{
		ID:                "decision-semantic",
		Verdict:           string(contracts.VerdictEscalate),
		Reason:            "semantic review required",
		ReasonCode:        string(contracts.ReasonSemanticThreatEscalate),
		PhenotypeHash:     "sha256:phenotype",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      "sha256:effect",
		ThreatScan: &contracts.ThreatScanRef{
			ScanID:       "scan-semantic",
			MaxSeverity:  contracts.ThreatSeverityInfo,
			FindingCount: 1,
			TrustLevel:   contracts.InputTrustTainted,
			InputHash:    "sha256:input",
			Semantic: &contracts.SemanticThreatAssessment{
				Available:      true,
				ModelVersion:   "semantic-advisory.v1",
				ModelHash:      "sha256:model",
				ThresholdBP:    7000,
				MaxBP:          7042,
				NearestClass:   string(contracts.ThreatClassPromptInjection),
				Flagged:        true,
				InputTruncated: false,
			},
		},
	}
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	if decision.SignatureVersion != contracts.DecisionRecordSignatureV3 {
		t.Fatalf("signature version = %q, want %q", decision.SignatureVersion, contracts.DecisionRecordSignatureV3)
	}
	if valid, verifyErr := signer.VerifyDecision(decision); verifyErr != nil || !valid {
		t.Fatalf("verify original: valid=%v err=%v", valid, verifyErr)
	}

	threat := *decision.ThreatScan
	semantic := *threat.Semantic
	semantic.MaxBP--
	threat.Semantic = &semantic
	tampered := *decision
	tampered.ThreatScan = &threat
	if valid, verifyErr := signer.VerifyDecision(&tampered); verifyErr == nil && valid {
		t.Fatal("semantic score mutation verified")
	}

	stripped := *decision
	stripped.ThreatScan = nil
	if valid, verifyErr := signer.VerifyDecision(&stripped); verifyErr == nil && valid {
		t.Fatal("stripped threat evidence verified")
	}
}

func TestDecisionV3RequiresTypedThreatEvidence(t *testing.T) {
	decision := &contracts.DecisionRecord{
		ID:               "decision-semantic-missing",
		Verdict:          string(contracts.VerdictEscalate),
		SignatureVersion: contracts.DecisionRecordSignatureV3,
	}
	if _, err := DecisionVerifyPayload(decision); err == nil {
		t.Fatal("V3 verification accepted missing typed threat evidence")
	}
}
