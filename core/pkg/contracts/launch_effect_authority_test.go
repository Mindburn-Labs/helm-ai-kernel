package contracts_test

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestLaunchEffectAuthorizationEnvelopeVerifiesEveryAuthorityBinding(t *testing.T) {
	envelope, ctx, _, publicKey := launchAuthorizationFixture(t)
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/launch_effect_envelope.v1.json"), envelope); err != nil {
		t.Fatalf("signed launch authorization envelope rejected by schema: %v", err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("signed launch authorization envelope rejected: %v", err)
	}
	if envelope.KernelVerdictHash != "sha256:4963424fab50a1087ddc5a079c0113193d338a2661bc8d038fd7853af0ce1c45" {
		t.Fatalf("launch verdict hash = %s, want committed golden", envelope.KernelVerdictHash)
	}
	if envelope.KernelVerdictSignature != "ed25519:c5552cd0e67af119612469a38aa6d4638ecdd1dca0ad8de743edd53a76fe6adf80cd7ce300689e8a3ce5c63854c388a48342dfce7cfa85cb6b9f8eb9cc392804" {
		t.Fatalf("launch verdict signature = %s, want committed golden", envelope.KernelVerdictSignature)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("fixture public key is invalid")
	}
}

func TestLaunchEffectAuthorizationEnvelopeFailsClosed(t *testing.T) {
	base, baseContext, privateKey, _ := launchAuthorizationFixture(t)
	tests := []struct {
		name   string
		mutate func(*contracts.LaunchEffectAuthorizationEnvelope, *contracts.LaunchEffectEnvelopeVerificationContext)
		resign bool
	}{
		{name: "outer input identity", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.TenantID = "tenant-cross-boundary"
		}},
		{name: "input schema hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.InputSchemaHash = launchHash("0")
		}},
		{name: "uppercase input schema hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.InputSchemaHash = "sha256:" + strings.Repeat("A", 64)
		}},
		{name: "missing schema validator", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ValidateInput = nil
		}},
		{name: "missing provider route validator", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ValidateProviderRoute = nil
		}},
		{name: "canonical input hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.InputHash = launchHash("0")
		}},
		{name: "idempotency key", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.IdempotencyKey = launchHash("0")
		}},
		{name: "effect permit hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.EffectPermitHash = launchHash("9")
		}},
		{name: "canonical request", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.RequestBodyHash = launchHash("0")
		}},
		{name: "connector action", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.ActionURN = contracts.LaunchActionProviderTeardown
		}},
		{name: "permit nonce", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.PermitNonce = "different_nonce_0123456789"
		}},
		{name: "noncanonical permit nonce", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.PermitNonce = "invalid.nonce.0123456789"
		}},
		{name: "policy epoch", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.PolicyEpoch = "epoch-stale"
		}},
		{name: "emergency fence", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.EmergencyFenceEpoch = 3
		}},
		{name: "dispatch after permit", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.DispatchDeadline = "2026-07-18T12:06:00Z"
		}},
		{name: "permit exceeds source-owned TTL", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.MaximumPermitTTL = 4 * time.Minute
		}},
		{name: "expired verdict", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.Now = time.Date(2026, 7, 18, 12, 7, 0, 0, time.UTC)
		}},
		{name: "untrusted verdict signer", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveVerdictKey = func(string) (ed25519.PublicKey, error) { return nil, fmt.Errorf("key absent from trust root") }
		}},
		{name: "missing atomic permit consumer", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ConsumePermit = nil
		}},
		{name: "signature", mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.KernelVerdictSignature = "ed25519:" + strings.Repeat("0", 128)
		}},
		{name: "uppercase signature encoding", mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.KernelVerdictSignature = "ed25519:" + strings.Repeat("A", 128)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := base
			envelope.Input = cloneLaunchInput(t, base.Input)
			ctx := baseContext
			test.mutate(&envelope, &ctx)
			if test.resign {
				var err error
				envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
				t.Fatal("authority-binding mutation was accepted")
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeConsumesPermitAtomically(t *testing.T) {
	envelope, ctx, _, _ := launchAuthorizationFixture(t)
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("first dispatch verification failed: %v", err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("replayed launch effect permit was accepted")
	}
}

func TestLaunchEffectAuthorizationEnvelopeDoesNotConsumeAfterFailedVerification(t *testing.T) {
	envelope, ctx, _, _ := launchAuthorizationFixture(t)
	tampered := envelope
	tampered.KernelVerdictSignature = "ed25519:" + strings.Repeat("0", 128)
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(tampered, ctx); err == nil {
		t.Fatal("tampered verdict unexpectedly verified")
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("failed verification consumed the permit: %v", err)
	}
}

func TestLaunchEffectAuthorizationEnvelopeVerifiesEveryPreviewEffect(t *testing.T) {
	for index, fixture := range launchInputFixtures() {
		index, fixture := index, fixture
		t.Run(fixture.effectID, func(t *testing.T) {
			envelope, ctx, _, _ := launchAuthorizationFixtureAt(t, index)
			if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/launch_effect_envelope.v1.json"), envelope); err != nil {
				t.Fatalf("launch authorization envelope rejected by schema: %v", err)
			}
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
				t.Fatalf("launch authorization envelope rejected: %v", err)
			}
		})
	}
}

func TestLaunchRollbackEnvelopeConsumesOnlyItsExactPreauthorization(t *testing.T) {
	envelope, ctx, privateKey, _ := launchAuthorizationFixtureAt(t, 3)
	envelope.ApprovalArtifactRef = "different-rollback-permit"
	envelope.ApprovalArtifactHash = launchHash("d")
	ctx.Permit.ApprovalArtifactRef = envelope.ApprovalArtifactRef
	ctx.Permit.ApprovalArtifactHash = envelope.ApprovalArtifactHash
	var err error
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Permit.KernelVerdictHash = envelope.KernelVerdictHash
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("rollback envelope accepted authority other than its exact nested rollback permit")
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsSchemaIncompleteCanonicalInput(t *testing.T) {
	envelope, ctx, privateKey, _ := launchAuthorizationFixture(t)
	envelope.Input = cloneLaunchInput(t, envelope.Input)
	delete(envelope.Input, "resource_graph_hash")
	key, err := contracts.DeriveLaunchEffectIdempotencyKey(envelope.EffectID, envelope.Input)
	if err != nil {
		t.Fatal(err)
	}
	envelope.InputHash = key
	envelope.IdempotencyKey = key
	ctx.Permit.InputHash = key
	ctx.Permit.IdempotencyKey = key
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("schema-incomplete canonical input passed the dispatch verifier")
	}
}

func TestLaunchEffectReceiptSigningRevisionAndStateMachine(t *testing.T) {
	privateKey := launchFixturePrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	verifyContext := launchReceiptVerificationContext(publicKey)
	receipt := launchUnknownReceiptFixture()
	signed, err := contracts.SignLaunchEffectReceipt(receipt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/launch_effect_receipt.v1.json"), signed); err != nil {
		t.Fatalf("signed receipt rejected by schema: %v", err)
	}
	if err := contracts.VerifyLaunchEffectReceipt(signed, verifyContext); err != nil {
		t.Fatalf("signed receipt rejected: %v", err)
	}
	if signed.ReceiptID != "9ce2cc4a1f1b25c6fba4b27ec2f30bb453dd2cbaade396d00a455a3258ec5a5c" {
		t.Fatalf("launch receipt ID = %s, want committed golden", signed.ReceiptID)
	}
	if signed.Signature != "lEShye5+nx8cmOZaU+C4vLqm9NWdt3Ahl5HxwxJfAms8t0iiOiMq0QWDrt994eWmWiCqecCRjk7afegLQjaLAw==" {
		t.Fatalf("launch receipt signature = %s, want committed golden", signed.Signature)
	}

	reconciled := signed
	reconciled.ReceiptID = ""
	reconciled.Signature = ""
	reconciled.ReceiptRevision = 2
	reconciled.ReconciliationRevision = 1
	reconciled.PreviousReceiptID = signed.ReceiptID
	reconciled.Outcome = "SUCCEEDED"
	reconciled.ReconciliationStatus = "PROVEN_APPLIED"
	reconciled.DependencyState = "RELEASED"
	reconciled.DependencyStateHash = launchHash("a")
	reconciled.ResultHash = launchHash("9")
	reconciled.ProviderOperationRef = "provider-operation-1"
	reconciled.ProviderResourceRefs = []string{"do:app:1", "do:deployment:1"}
	reconciled.EvidencePackRef = "evidencepack:launch:1"
	reconciled.EvidencePackHash = launchHash("8")
	reconciled.ProofGraphNode = launchHash("b")
	reconciled.Timestamp = "2026-07-18T12:04:00Z"
	reconciled.Lamport = 2
	reconciledSigned, err := contracts.SignLaunchEffectReceipt(reconciled, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectReceipt(reconciledSigned, verifyContext); err != nil {
		t.Fatalf("reconciled receipt rejected: %v", err)
	}
	if err := contracts.VerifyLaunchEffectReceiptRevision(reconciledSigned, signed, verifyContext); err != nil {
		t.Fatalf("receipt revision chain rejected: %v", err)
	}

	tampered := reconciledSigned
	tampered.ResultHash = launchHash("8")
	if err := contracts.VerifyLaunchEffectReceipt(tampered, verifyContext); err == nil {
		t.Fatal("tampered launch effect receipt verified")
	}

	unsafeUnknown := receipt
	unsafeUnknown.DependencyState = "RELEASED"
	if _, err := contracts.SignLaunchEffectReceipt(unsafeUnknown, privateKey); err == nil {
		t.Fatal("UNKNOWN receipt released dependent effects")
	}
	prematureEvidence := receipt
	prematureEvidence.EvidencePackRef = "evidencepack:premature"
	prematureEvidence.EvidencePackHash = launchHash("8")
	if _, err := contracts.SignLaunchEffectReceipt(prematureEvidence, privateKey); err == nil {
		t.Fatal("UNKNOWN receipt claimed a finalized EvidencePack")
	}

	brokenChain := reconciledSigned
	brokenChain.PreviousReceiptID = strings.Repeat("0", 64)
	brokenChain, err = contracts.SignLaunchEffectReceipt(brokenChain, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectReceiptRevision(brokenChain, signed, verifyContext); err == nil {
		t.Fatal("receipt revision with the wrong predecessor hash verified")
	}

	unreconciledFailure := receipt
	unreconciledFailure.Outcome = "FAILED"
	if _, err := contracts.SignLaunchEffectReceipt(unreconciledFailure, privateKey); err == nil {
		t.Fatal("FAILED receipt without terminal reconciliation proof was signed")
	}

	changedWithoutReconciliation := signed
	changedWithoutReconciliation.ReceiptID = ""
	changedWithoutReconciliation.Signature = ""
	changedWithoutReconciliation.ReceiptRevision = 2
	changedWithoutReconciliation.PreviousReceiptID = signed.ReceiptID
	changedWithoutReconciliation.ResultHash = launchHash("d")
	changedWithoutReconciliation.Timestamp = "2026-07-18T12:04:00Z"
	changedWithoutReconciliation.Lamport = 2
	changedWithoutReconciliationSigned, err := contracts.SignLaunchEffectReceipt(changedWithoutReconciliation, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectReceiptRevision(changedWithoutReconciliationSigned, signed, verifyContext); err == nil {
		t.Fatal("receipt reconciliation material changed without advancing reconciliation revision")
	}

	changedImmutable := reconciled
	changedImmutable.Principal = "workspace:other"
	changedImmutable.ReceiptChainID = ""
	changedImmutableSigned, err := contracts.SignLaunchEffectReceipt(changedImmutable, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectReceiptRevision(changedImmutableSigned, signed, verifyContext); err == nil {
		t.Fatal("receipt revision changed immutable principal")
	}
}

func TestLaunchEffectReceiptRejectsNoncanonicalAndUntrustedProof(t *testing.T) {
	privateKey := launchFixturePrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)

	unsorted := launchUnknownReceiptFixture()
	unsorted.ProviderResourceRefs = []string{"do:app:2", "do:app:1"}
	if _, err := contracts.SignLaunchEffectReceipt(unsorted, privateKey); err == nil {
		t.Fatal("receipt signed noncanonical provider resource reference order")
	}

	badNonce := launchUnknownReceiptFixture()
	badNonce.PermitNonce = "invalid.nonce.0123456789"
	if _, err := contracts.SignLaunchEffectReceipt(badNonce, privateKey); err == nil {
		t.Fatal("receipt signed a noncanonical permit nonce")
	}

	uppercaseHash := launchUnknownReceiptFixture()
	uppercaseHash.ResultHash = "sha256:" + strings.Repeat("A", 64)
	if _, err := contracts.SignLaunchEffectReceipt(uppercaseHash, privateKey); err == nil {
		t.Fatal("receipt signed an uppercase digest")
	}

	signed, err := contracts.SignLaunchEffectReceipt(launchUnknownReceiptFixture(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	badSignature := signed
	badSignature.Signature = strings.TrimRight(badSignature.Signature, "=")
	if err := contracts.VerifyLaunchEffectReceipt(badSignature, launchReceiptVerificationContext(publicKey)); err == nil {
		t.Fatal("receipt accepted noncanonical base64 signature")
	}

	untrusted := launchReceiptVerificationContext(publicKey)
	untrusted.ResolveSignerKey = func(string) (ed25519.PublicKey, error) {
		return nil, fmt.Errorf("key absent from trust root")
	}
	if err := contracts.VerifyLaunchEffectReceipt(signed, untrusted); err == nil {
		t.Fatal("receipt accepted signer absent from trust root")
	}

	missingProof := launchReceiptVerificationContext(publicKey)
	missingProof.VerifyProofGraphNode = func(string) error { return fmt.Errorf("node not found") }
	if err := contracts.VerifyLaunchEffectReceipt(signed, missingProof); err == nil {
		t.Fatal("receipt accepted a missing ProofGraph node")
	}
}

func launchAuthorizationFixture(t *testing.T) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	return launchAuthorizationFixtureAt(t, 0)
}

func launchAuthorizationFixtureAt(t *testing.T, fixtureIndex int) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	fixture := launchInputFixtures()[fixtureIndex]
	input := cloneLaunchInput(t, fixture.input)
	contract := contracts.LookupLaunchMissionEffectPreview(fixture.effectID)
	if contract == nil {
		t.Fatalf("missing launch effect contract for %s", fixture.effectID)
	}
	key, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, input)
	if err != nil {
		t.Fatal(err)
	}
	approvalRef := "commercial-approval-1"
	approvalHash := launchHash("f")
	switch fixture.effectID {
	case contracts.EffectTypeDeployProductionActivate:
		approvalRef = input["promotion_permit_ref"].(string)
		approvalHash = input["promotion_permit_hash"].(string)
	case contracts.EffectTypeProviderRollback:
		approvalRef = input["rollback_permit_ref"].(string)
		approvalHash = input["rollback_permit_hash"].(string)
	case contracts.EffectTypeProviderTeardown:
		approvalRef = input["fresh_teardown_approval_ref"].(string)
		approvalHash = input["fresh_teardown_approval_hash"].(string)
	}
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	verdictIssuedAt := now.Add(-time.Minute)
	verdictExpiry := now.Add(6 * time.Minute)
	permitIssuedAt := now
	expiry := now.Add(5 * time.Minute)
	deadline := now.Add(4 * time.Minute)
	envelope := contracts.LaunchEffectAuthorizationEnvelope{
		SchemaVersion:          contracts.LaunchEffectEnvelopeSchemaVersion,
		EffectID:               fixture.effectID,
		TenantID:               "tenant-1",
		WorkspaceID:            "workspace-1",
		MissionID:              "mission-1",
		EffectOrdinal:          input["effect_ordinal"].(int),
		InputSchemaRef:         fixture.schema,
		InputSchemaHash:        launchHash("e"),
		Input:                  input,
		InputHash:              key,
		IdempotencyKey:         key,
		PlanHash:               input["plan_hash"].(string),
		ApprovalArtifactRef:    approvalRef,
		ApprovalArtifactHash:   approvalHash,
		PolicyEpoch:            "epoch-1",
		EmergencyFenceEpoch:    4,
		Verdict:                "ALLOW",
		KernelVerdictRef:       "verdict-1",
		KernelVerdictIssuedAt:  verdictIssuedAt.Format(time.RFC3339Nano),
		KernelVerdictExpiry:    verdictExpiry.Format(time.RFC3339Nano),
		KernelVerdictSignerKey: "kernel-key-1",
		EffectPermitRef:        "permit-1",
		EffectPermitHash:       launchHash("0"),
		PermitNonce:            "0123456789abcdefABCDEF",
		PermitIssuedAt:         permitIssuedAt.Format(time.RFC3339Nano),
		PermitExpiry:           expiry.Format(time.RFC3339Nano),
		ProofSessionRef:        "proof-session-1",
		EvidenceReservationRef: "evidence-reservation-1",
		ConnectorID:            contract.ConnectorID,
		ConnectorContractHash:  input["connector_contract_hash"].(string),
		ActionURN:              contract.ActionURN,
		RequestBodyHash:        launchHash("1"),
		ArgsC14NHash:           launchHash("2"),
		DispatchDeadline:       deadline.Format(time.RFC3339Nano),
		ReplayHint:             "single_use_permit",
	}
	privateKey := launchFixturePrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	permit := contracts.LaunchEffectPermitBinding{
		EffectPermitRef:       envelope.EffectPermitRef,
		EffectPermitHash:      envelope.EffectPermitHash,
		PermitNonce:           envelope.PermitNonce,
		PermitIssuedAt:        permitIssuedAt,
		PermitExpiry:          expiry,
		KernelVerdictRef:      envelope.KernelVerdictRef,
		KernelVerdictHash:     envelope.KernelVerdictHash,
		KernelVerdictIssuedAt: verdictIssuedAt,
		KernelVerdictExpiry:   verdictExpiry,
		EffectID:              envelope.EffectID,
		TenantID:              envelope.TenantID,
		WorkspaceID:           envelope.WorkspaceID,
		MissionID:             envelope.MissionID,
		EffectOrdinal:         envelope.EffectOrdinal,
		InputSchemaHash:       envelope.InputSchemaHash,
		InputHash:             envelope.InputHash,
		IdempotencyKey:        envelope.IdempotencyKey,
		PlanHash:              envelope.PlanHash,
		ApprovalArtifactRef:   envelope.ApprovalArtifactRef,
		ApprovalArtifactHash:  envelope.ApprovalArtifactHash,
		ConnectorID:           envelope.ConnectorID,
		ConnectorContractHash: envelope.ConnectorContractHash,
		ActionURN:             envelope.ActionURN,
		RequestBodyHash:       envelope.RequestBodyHash,
		ArgsC14NHash:          envelope.ArgsC14NHash,
		PolicyEpoch:           envelope.PolicyEpoch,
		EmergencyFenceEpoch:   envelope.EmergencyFenceEpoch,
		DispatchDeadline:      deadline,
		SingleUse:             true,
	}
	var consumed atomic.Bool
	ctx := contracts.LaunchEffectEnvelopeVerificationContext{
		Now: now,
		ValidateInput: func(schemaRef, schemaHash string, candidate map[string]any) error {
			if schemaRef != envelope.InputSchemaRef || schemaHash != envelope.InputSchemaHash {
				return fmt.Errorf("unexpected schema identity")
			}
			return compileSchema(t, schemaRef).Validate(candidate)
		},
		ValidateProviderRoute:   validateDigitalOceanEU50Route,
		ExpectedInputSchemaHash: envelope.InputSchemaHash,
		ExpectedRequestBodyHash: envelope.RequestBodyHash,
		ExpectedArgsC14NHash:    envelope.ArgsC14NHash,
		ExpectedPolicyEpoch:     envelope.PolicyEpoch,
		CurrentEmergencyFence:   envelope.EmergencyFenceEpoch,
		MaximumPermitTTL:        5 * time.Minute,
		ResolveVerdictKey: func(signerKeyID string) (ed25519.PublicKey, error) {
			if signerKeyID != envelope.KernelVerdictSignerKey {
				return nil, fmt.Errorf("unknown verdict signer key")
			}
			return publicKey, nil
		},
		ConsumePermit: func(expected contracts.LaunchEffectPermitBinding) error {
			if expected.EffectPermitRef != permit.EffectPermitRef || expected.PermitNonce != permit.PermitNonce {
				return fmt.Errorf("permit compare-and-swap binding mismatch")
			}
			if !consumed.CompareAndSwap(false, true) {
				return fmt.Errorf("permit already consumed")
			}
			return nil
		},
		Permit: permit,
	}
	return envelope, ctx, privateKey, publicKey
}

func launchUnknownReceiptFixture() contracts.LaunchEffectReceipt {
	return contracts.LaunchEffectReceipt{
		SchemaVersion:          contracts.LaunchEffectReceiptSchemaVersion,
		ReceiptVersion:         contracts.LaunchEffectReceiptVersion,
		Kind:                   "helm_native_receipt",
		ReceiptRevision:        1,
		ReconciliationRevision: 0,
		DecisionID:             "verdict-1",
		EffectID:               contracts.EffectTypeProviderProvision,
		Verdict:                "ALLOW",
		Principal:              "workspace:workspace-1",
		Tool:                   contracts.LaunchConnectorProviderRoute,
		Action:                 contracts.LaunchActionProviderProvision,
		Timestamp:              "2026-07-18T12:03:00Z",
		Lamport:                1,
		ProofGraphNode:         launchHash("0"),
		SignerKeyID:            "kernel-key-1",
		PayloadHash:            launchHash("3"),
		Metadata: contracts.LaunchEffectReceiptMetadata{
			Profile:              contracts.LaunchEffectReceiptProfile,
			RedactionProfileHash: launchHash("7"),
		},
		TenantID:              "tenant-1",
		WorkspaceID:           "workspace-1",
		MissionID:             "mission-1",
		EffectOrdinal:         1,
		InputSchemaHash:       launchHash("d"),
		InputHash:             launchHash("1"),
		IdempotencyKey:        launchHash("2"),
		RequestHash:           launchHash("3"),
		ResultHash:            launchHash("4"),
		KernelVerdictRef:      "verdict-1",
		KernelVerdictHash:     launchHash("5"),
		ApprovalArtifactRef:   "commercial-approval-1",
		ApprovalArtifactHash:  launchHash("f"),
		EffectPermitRef:       "permit-1",
		EffectPermitHash:      launchHash("c"),
		PermitNonce:           "0123456789abcdefABCDEF",
		PermitConsumptionRef:  "permit-consumption-1",
		PermitConsumptionHash: launchHash("b"),
		PolicyEpoch:           "epoch-1",
		EmergencyFenceEpoch:   4,
		ConnectorContractHash: launchHash("6"),
		ReconciliationLocator: launchHash("e"),
		Outcome:               "UNKNOWN",
		ReconciliationStatus:  "PENDING",
		DependencyState:       "FROZEN",
		DependencySetHash:     launchHash("8"),
		DependencyStateHash:   launchHash("9"),
	}
}

func launchReceiptVerificationContext(publicKey ed25519.PublicKey) contracts.LaunchEffectReceiptVerificationContext {
	return contracts.LaunchEffectReceiptVerificationContext{
		MinimumLamport: 1,
		ResolveSignerKey: func(signerKeyID string) (ed25519.PublicKey, error) {
			if signerKeyID != "kernel-key-1" {
				return nil, fmt.Errorf("unknown receipt signer key")
			}
			return publicKey, nil
		},
		VerifyProofGraphNode: func(nodeHash string) error {
			if !strings.HasPrefix(nodeHash, "sha256:") {
				return fmt.Errorf("invalid ProofGraph node")
			}
			return nil
		},
	}
}

func launchFixturePrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
}
