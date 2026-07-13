package crypto

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type decisionSigner interface {
	SignDecision(*contracts.DecisionRecord) error
}

type decisionVerifier interface {
	VerifyDecision(*contracts.DecisionRecord) (bool, error)
}

func requestBoundDecision() *contracts.DecisionRecord {
	return &contracts.DecisionRecord{
		ID:                     "dec-v2-001",
		ProposalID:             "proposal-001",
		StepID:                 "step-001",
		PhenotypeHash:          "sha256:phenotype",
		PolicyVersion:          "sha256:policy-version",
		SubjectID:              "principal:alice",
		Action:                 "EXECUTE_TOOL",
		Resource:               "files.write",
		EffectDigest:           "sha256:effect",
		PolicyBackend:          "helm",
		PolicyContentHash:      "sha256:policy-content",
		PolicyEpoch:            "42",
		PolicyDecisionHash:     "sha256:policy-decision",
		StateCursor:            "cursor-001",
		Snapshot:               "sha256:snapshot",
		EnvFingerprint:         "sha256:environment",
		Verdict:                string(contracts.VerdictAllow),
		Reason:                 "policy permits this governed effect",
		ReasonCode:             "POLICY_ALLOW",
		TrajectoryRiskScore:    0.125,
		SessionCentroidHash:    "sha256:centroid",
		RiskAccumulationWindow: 3,
		RequirementSetHash:     "sha256:requirements",
		Timestamp:              time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC),
		Intervention: &contracts.InterventionMetadata{
			Type:        contracts.InterventionThrottle,
			ReasonCode:  "RATE_LIMITED",
			TokensSaved: 11,
		},
	}
}

func TestDecisionSignatureSchemaV2_BindsRequestAcrossSigners(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		new  func(*testing.T) (decisionSigner, decisionVerifier)
	}{
		{
			name: "ed25519",
			new: func(t *testing.T) (decisionSigner, decisionVerifier) {
				t.Helper()
				signer, err := NewEd25519Signer("v2-ed25519")
				if err != nil {
					t.Fatalf("NewEd25519Signer: %v", err)
				}
				verifier, err := NewEd25519Verifier(signer.PublicKeyBytes())
				if err != nil {
					t.Fatalf("NewEd25519Verifier: %v", err)
				}
				return signer, verifier
			},
		},
		{
			name: "ml-dsa-65",
			new: func(t *testing.T) (decisionSigner, decisionVerifier) {
				t.Helper()
				signer, err := NewMLDSASigner("v2-mldsa")
				if err != nil {
					t.Fatalf("NewMLDSASigner: %v", err)
				}
				verifier, err := NewMLDSAVerifier(signer.PublicKeyBytes())
				if err != nil {
					t.Fatalf("NewMLDSAVerifier: %v", err)
				}
				return signer, verifier
			},
		},
		{
			name: "hybrid",
			new: func(t *testing.T) (decisionSigner, decisionVerifier) {
				t.Helper()
				signer, err := NewHybridSigner("v2-hybrid")
				if err != nil {
					t.Fatalf("NewHybridSigner: %v", err)
				}
				verifier, err := NewHybridVerifier(signer.Ed25519Signer().PublicKeyBytes(), signer.MLDSASigner().PublicKeyBytes())
				if err != nil {
					t.Fatalf("NewHybridVerifier: %v", err)
				}
				return signer, verifier
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, verifier := tc.new(t)
			decision := requestBoundDecision()
			if err := signer.SignDecision(decision); err != nil {
				t.Fatalf("SignDecision: %v", err)
			}
			if decision.SignatureSchema != DecisionSignatureSchemaV2 {
				t.Fatalf("SignatureSchema = %q, want %q", decision.SignatureSchema, DecisionSignatureSchemaV2)
			}

			valid, err := verifier.VerifyDecision(decision)
			if err != nil || !valid {
				t.Fatalf("VerifyDecision before tampering = %v, %v; want true, nil", valid, err)
			}

			mutations := map[string]func(*contracts.DecisionRecord){
				"subject":        func(d *contracts.DecisionRecord) { d.SubjectID = "principal:mallory" },
				"action":         func(d *contracts.DecisionRecord) { d.Action = "DELETE_TOOL" },
				"resource":       func(d *contracts.DecisionRecord) { d.Resource = "billing.refund" },
				"policy":         func(d *contracts.DecisionRecord) { d.PolicyContentHash = "sha256:tampered-policy" },
				"signature type": func(d *contracts.DecisionRecord) { d.SignatureType = "ed25519:other-key" },
			}

			for name, mutate := range mutations {
				t.Run(name, func(t *testing.T) {
					tampered := *decision
					mutate(&tampered)
					valid, err := verifier.VerifyDecision(&tampered)
					if err == nil && valid {
						t.Fatal("tampered decision verified")
					}
				})
			}
		})
	}
}

func TestDecisionSignatureSchemaV2_KeyRingRejectsRequestTampering(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		new  func(*testing.T) Signer
	}{
		{
			name: "ed25519",
			new: func(t *testing.T) Signer {
				t.Helper()
				signer, err := NewEd25519Signer("v2-keyring-ed25519")
				if err != nil {
					t.Fatalf("NewEd25519Signer: %v", err)
				}
				return signer
			},
		},
		{
			name: "ml-dsa-65",
			new: func(t *testing.T) Signer {
				t.Helper()
				signer, err := NewMLDSASigner("v2-keyring-mldsa")
				if err != nil {
					t.Fatalf("NewMLDSASigner: %v", err)
				}
				return signer
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ring := NewKeyRing()
			ring.AddKey(tc.new(t))

			decision := requestBoundDecision()
			if err := ring.SignDecision(decision); err != nil {
				t.Fatalf("SignDecision: %v", err)
			}
			decision.Resource = "connector.untrusted"

			valid, err := ring.VerifyDecision(decision)
			if err == nil && valid {
				t.Fatal("KeyRing accepted a request-tampered v2 decision")
			}
		})
	}
}

func TestDecisionSignatureSchemaV2_VerifiesLegacyV1(t *testing.T) {
	t.Parallel()

	signer, err := NewEd25519Signer("legacy-v1")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	decision := requestBoundDecision()
	decision.SignatureSchema = ""
	decision.SignatureType = SigPrefixEd25519 + SigSeparator + signer.KeyID

	signature, err := signer.Sign([]byte(CanonicalizeDecision(
		decision.ID,
		decision.Verdict,
		decision.Reason,
		decision.PhenotypeHash,
		decision.PolicyContentHash,
		decision.EffectDigest,
	)))
	if err != nil {
		t.Fatalf("sign legacy payload: %v", err)
	}
	decision.Signature = signature

	valid, err := signer.VerifyDecision(decision)
	if err != nil || !valid {
		t.Fatalf("VerifyDecision legacy v1 = %v, %v; want true, nil", valid, err)
	}
}

func TestDecisionSignatureSchemaV2_VerifiesAfterJSONRoundTrip(t *testing.T) {
	t.Parallel()

	signer, err := NewEd25519Signer("json-round-trip")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	decision := requestBoundDecision()
	if err := signer.SignDecision(decision); err != nil {
		t.Fatalf("SignDecision: %v", err)
	}

	encoded, err := contracts.EncodeDecisionRecord(decision)
	if err != nil {
		t.Fatalf("EncodeDecisionRecord: %v", err)
	}
	decoded, err := contracts.DecodeDecisionRecord(encoded)
	if err != nil {
		t.Fatalf("DecodeDecisionRecord: %v", err)
	}
	verifier, err := NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatalf("NewEd25519Verifier: %v", err)
	}
	valid, err := verifier.VerifyDecision(decoded)
	if err != nil || !valid {
		t.Fatalf("VerifyDecision after JSON round trip = %v, %v; want true, nil", valid, err)
	}
}

func TestDecisionSignatureSchemaV2_RejectsUnsupportedOrIncompleteSchema(t *testing.T) {
	t.Parallel()

	signer, err := NewEd25519Signer("schema-errors")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}

	unsupported := requestBoundDecision()
	unsupported.SignatureSchema = "helm.decision.signature.v999"
	if err := signer.SignDecision(unsupported); err == nil {
		t.Fatal("SignDecision accepted an unsupported schema")
	}

	incomplete := requestBoundDecision()
	incomplete.SignatureSchema = DecisionSignatureSchemaV2
	incomplete.Resource = ""
	if err := signer.SignDecision(incomplete); err == nil {
		t.Fatal("SignDecision accepted an incomplete v2 request binding")
	}
}

func TestCanonicalizeDecisionV2_AvoidsDelimiterAmbiguity(t *testing.T) {
	t.Parallel()

	first := requestBoundDecision()
	first.SignatureSchema = DecisionSignatureSchemaV2
	first.SignatureType = "ed25519:key-1"
	first.SubjectID = "tenant:alice"
	first.Action = "tool:write"

	second := requestBoundDecision()
	second.SignatureSchema = DecisionSignatureSchemaV2
	second.SignatureType = "ed25519:key-1"
	second.SubjectID = "tenant"
	second.Action = "alice:tool:write"

	firstPayload, err := CanonicalizeDecisionV2(first)
	if err != nil {
		t.Fatalf("CanonicalizeDecisionV2 first: %v", err)
	}
	secondPayload, err := CanonicalizeDecisionV2(second)
	if err != nil {
		t.Fatalf("CanonicalizeDecisionV2 second: %v", err)
	}
	if string(firstPayload) == string(secondPayload) {
		t.Fatal("distinct request bindings produced the same v2 canonical payload")
	}
}
