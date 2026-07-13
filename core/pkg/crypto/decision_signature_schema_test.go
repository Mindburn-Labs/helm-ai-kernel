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
				"schema downgrade": func(d *contracts.DecisionRecord) {
					d.SignatureSchema = ""
				},
				"unknown schema": func(d *contracts.DecisionRecord) {
					d.SignatureSchema = "helm.decision.signature.v999"
				},
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
	if err := RequireExecutableDecisionSignature(decision); err == nil {
		t.Fatal("legacy v1 decision was accepted for execution")
	}
}

func TestDecisionSignatureSchemaV2_RequiresRequestBindingForExecution(t *testing.T) {
	t.Parallel()

	decision := requestBoundDecision()
	decision.SignatureSchema = DecisionSignatureSchemaV2
	if err := RequireExecutableDecisionSignature(decision); err != nil {
		t.Fatalf("complete v2 decision rejected for execution: %v", err)
	}

	decision.Action = ""
	if err := RequireExecutableDecisionSignature(decision); err == nil {
		t.Fatal("incomplete v2 request binding was accepted for execution")
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

func keyringIntentFixture() *contracts.AuthorizedExecutionIntent {
	issuedAt := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	return &contracts.AuthorizedExecutionIntent{
		ID:               "intent-keyring-v2",
		DecisionID:       "decision-keyring-v2",
		EffectDigestHash: "sha256:effect-keyring-v2",
		IdempotencyKey:   "idempotency-keyring-v2",
		IssuedAt:         issuedAt,
		ExpiresAt:        issuedAt.Add(time.Minute),
		Signer:           "kernel-keyring-v2",
		AllowedTool:      "files.write",
	}
}

func keyringReceiptFixture() *contracts.Receipt {
	return &contracts.Receipt{
		ReceiptID:           "receipt-keyring-v2",
		DecisionID:          "decision-keyring-v2",
		EffectID:            "effect-keyring-v2",
		ExternalReferenceID: "intent-keyring-v2",
		Status:              "SUCCEEDED",
		Timestamp:           time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC),
		ExecutorID:          "kernel-keyring-v2",
		Type:                contracts.ReceiptTypeExecution,
		SessionID:           "session-keyring-v2",
		LamportClock:        1,
		ArgsHash:            "sha256:args-keyring-v2",
	}
}

func resignCanonicalPayload(t *testing.T, signer *Ed25519Signer, payload []byte) string {
	t.Helper()
	signature, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign canonical payload: %v", err)
	}
	return signature
}

func TestKeyRingV2RejectsSignerAlgorithmAndProfileConfusion(t *testing.T) {
	t.Parallel()

	signer, err := NewEd25519Signer("keyring-identity")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	ring := NewKeyRing()
	ring.AddKey(signer)

	t.Run("decision algorithm claim", func(t *testing.T) {
		decision := requestBoundDecision()
		if err := signer.SignDecision(decision); err != nil {
			t.Fatalf("SignDecision: %v", err)
		}
		decision.SignatureType = SigPrefixHybrid + SigSeparator + signer.KeyID
		payload, err := CanonicalDecisionPayload(decision)
		if err != nil {
			t.Fatalf("CanonicalDecisionPayload: %v", err)
		}
		decision.Signature = resignCanonicalPayload(t, signer, payload)

		if valid, err := ring.VerifyDecision(decision); err == nil || valid {
			t.Fatalf("keyring accepted an Ed25519 decision relabelled as hybrid: valid=%v err=%v", valid, err)
		}
	})

	t.Run("intent algorithm claim", func(t *testing.T) {
		intent := keyringIntentFixture()
		if err := signer.SignIntent(intent); err != nil {
			t.Fatalf("SignIntent: %v", err)
		}
		intent.SignatureType = SigPrefixHybrid + SigSeparator + signer.KeyID
		payload, err := CanonicalIntentPayload(intent)
		if err != nil {
			t.Fatalf("CanonicalIntentPayload: %v", err)
		}
		intent.Signature = resignCanonicalPayload(t, signer, payload)

		if valid, err := ring.VerifyIntent(intent); err == nil || valid {
			t.Fatalf("keyring accepted an Ed25519 intent relabelled as hybrid: valid=%v err=%v", valid, err)
		}
	})

	t.Run("receipt profile and keyset claim", func(t *testing.T) {
		receipt := keyringReceiptFixture()
		if err := signer.SignReceipt(receipt); err != nil {
			t.Fatalf("SignReceipt: %v", err)
		}
		receipt.SignatureAlgorithm = SigPrefixHybrid
		receipt.SignatureProfile = ReceiptProfileHybrid
		receipt.PublicKeySet = map[string]string{
			SigPrefixEd25519: signer.PublicKey(),
			SigPrefixMLDSA65: "attacker-controlled-ml-dsa-key",
		}
		payload, err := CanonicalReceiptPayload(receipt)
		if err != nil {
			t.Fatalf("CanonicalReceiptPayload: %v", err)
		}
		receipt.Signature = resignCanonicalPayload(t, signer, payload)

		if valid, err := ring.VerifyReceipt(receipt); err == nil || valid {
			t.Fatalf("keyring accepted an Ed25519 receipt relabelled as hybrid: valid=%v err=%v", valid, err)
		}
	})

	t.Run("malformed intent signature type", func(t *testing.T) {
		intent := keyringIntentFixture()
		if err := signer.SignIntent(intent); err != nil {
			t.Fatalf("SignIntent: %v", err)
		}
		intent.SignatureType = "malformed"
		payload, err := CanonicalIntentPayload(intent)
		if err != nil {
			t.Fatalf("CanonicalIntentPayload: %v", err)
		}
		intent.Signature = resignCanonicalPayload(t, signer, payload)

		if valid, err := ring.VerifyIntent(intent); err == nil || valid {
			t.Fatalf("keyring accepted malformed non-empty intent signature type: valid=%v err=%v", valid, err)
		}
	})
}

func TestReceiptSignatureSchemaV2BindsMetadataAndEvidence(t *testing.T) {
	signer, err := NewEd25519Signer("receipt-evidence-binding")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	issuedAt := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	receipt := &contracts.Receipt{
		Type:         contracts.ReceiptTypeDecision,
		ReceiptID:    "receipt-evidence-binding",
		DecisionID:   "decision-evidence-binding",
		EffectID:     "LLM_INFERENCE",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    issuedAt,
		ExecutorID:   "kernel",
		SessionID:    "session-evidence-binding",
		LamportClock: 1,
		Metadata: map[string]any{
			"source":   "openai.proxy",
			"action":   "LLM_INFERENCE",
			"resource": "model:trusted",
		},
		GatewayID:      "gateway-1",
		RuntimeType:    "vllm",
		RuntimeVersion: "1.2.3",
		ModelHash:      "sha256:model",
		Evidence:       map[string]string{"network": "cas://network-log"},
		Action:         "LLM_INFERENCE",
		Provenance: &contracts.ReceiptProvenance{
			GeneratedBy: "kernel",
			GeneratedAt: issuedAt,
			Context:     "production",
		},
	}
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}
	if valid, err := signer.VerifyReceipt(receipt); err != nil || !valid {
		t.Fatalf("VerifyReceipt before tampering = %v, %v", valid, err)
	}

	mutations := map[string]func(*contracts.Receipt){
		"metadata": func(r *contracts.Receipt) {
			r.Metadata = map[string]any{"source": "openai.proxy", "resource": "model:attacker"}
		},
		"gateway":         func(r *contracts.Receipt) { r.GatewayID = "gateway-attacker" },
		"runtime version": func(r *contracts.Receipt) { r.RuntimeVersion = "9.9.9" },
		"model hash":      func(r *contracts.Receipt) { r.ModelHash = "sha256:attacker" },
		"evidence": func(r *contracts.Receipt) {
			r.Evidence = map[string]string{"network": "cas://forged-network-log"}
		},
		"provenance": func(r *contracts.Receipt) { r.Provenance.Context = "simulation" },
		"action":     func(r *contracts.Receipt) { r.Action = "BILLING_TRANSFER" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			tampered := *receipt
			if receipt.Provenance != nil {
				provenance := *receipt.Provenance
				tampered.Provenance = &provenance
			}
			mutate(&tampered)
			if valid, err := signer.VerifyReceipt(&tampered); err == nil && valid {
				t.Fatalf("receipt verified after %s tampering", name)
			}
		})
	}
}
