package approvalceremony

// quantum_posture: tests the classical Ed25519 connector effect-close
// acknowledgement and receipt signing; no post-quantum claim.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestEffectCloseSignaturesUseIndependentDomainsAndPinnedKeys(t *testing.T) {
	now := time.Date(2026, 7, 18, 10, 11, 12, 123456000, time.UTC)
	connectorSigner := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, ed25519.SeedSize)), "connector-ack-a",
	)
	acknowledgement := effectCloseSignatureAcknowledgement(t, now)
	envelope, err := SignConnectorEffectAcknowledgement(acknowledgement, connectorSigner)
	if err != nil {
		t.Fatal(err)
	}
	trustedKey := TrustedEffectAcknowledgementKey{
		IssuerID: acknowledgement.IssuerID, SigningKeyRef: acknowledgement.SigningKeyRef,
		ConnectorID: acknowledgement.ConnectorID, ConnectorVersion: acknowledgement.ConnectorVersion,
		PublicKey: connectorSigner.PublicKeyBytes(), Enabled: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}
	verifier, err := NewEd25519EffectAcknowledgementVerifier([]TrustedEffectAcknowledgementKey{trustedKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyEnvelope(envelope); err != nil {
		t.Fatalf("VerifyEnvelope(): %v", err)
	}
	mutated := envelope
	mutated.Acknowledgement.IntentRef = "other-intent"
	if err := verifier.VerifyEnvelope(mutated); !errors.Is(err, ErrEffectAcknowledgementRejected) {
		t.Fatalf("mutated acknowledgement signature error = %v", err)
	}
	disabledKey := trustedKey
	disabledKey.Enabled = false
	disabledVerifier, err := NewEd25519EffectAcknowledgementVerifier([]TrustedEffectAcknowledgementKey{disabledKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := disabledVerifier.VerifyEnvelope(envelope); !errors.Is(err, ErrEffectAcknowledgementRejected) {
		t.Fatalf("disabled acknowledgement key error = %v", err)
	}
	// A key disabled after observation must still verify an already-stored
	// acknowledgement so recovery/idempotency of an existing closure works.
	if err := disabledVerifier.VerifyStoredEnvelope(envelope); err != nil {
		t.Fatalf("VerifyStoredEnvelope() with a disabled-after-observation key = %v, want nil", err)
	}
	if err := disabledVerifier.VerifyStoredEnvelope(mutated); !errors.Is(err, ErrEffectAcknowledgementRejected) {
		t.Fatalf("VerifyStoredEnvelope() with a tampered acknowledgement = %v, want rejected", err)
	}
	futureKey := trustedKey
	futureKey.NotBefore = now.Add(time.Second)
	futureKey.NotAfter = now.Add(time.Hour)
	futureVerifier, err := NewEd25519EffectAcknowledgementVerifier([]TrustedEffectAcknowledgementKey{futureKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := futureVerifier.VerifyEnvelope(envelope); !errors.Is(err, ErrEffectAcknowledgementRejected) {
		t.Fatalf("out-of-lifetime acknowledgement error = %v", err)
	}
	otherReleaseKey := trustedKey
	otherReleaseKey.ConnectorVersion = "2.0.0"
	otherReleaseVerifier, err := NewEd25519EffectAcknowledgementVerifier([]TrustedEffectAcknowledgementKey{otherReleaseKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := otherReleaseVerifier.VerifyEnvelope(envelope); !errors.Is(err, ErrEffectAcknowledgementRejected) {
		t.Fatalf("other-release acknowledgement key error = %v", err)
	}
	if _, err := NewEd25519EffectAcknowledgementVerifier([]TrustedEffectAcknowledgementKey{trustedKey, trustedKey}); !errors.Is(err, ErrEffectAcknowledgementRejected) {
		t.Fatalf("duplicate acknowledgement key error = %v", err)
	}

	kernelSigner := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{62}, ed25519.SeedSize)), "kernel-close-a",
	)
	receipt := effectCloseSignatureReceipt(t, acknowledgement, now.Add(time.Second))
	signature, err := SignEffectCloseReceipt(receipt, kernelSigner)
	if err != nil {
		t.Fatal(err)
	}
	kernelVerifier, err := NewEd25519GrantSignatureVerifier(
		kernelSigner.PublicKeyBytes(), receipt.SigningKeyRef, receipt.KernelTrustRootID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := kernelVerifier.VerifyEffectCloseReceiptSignature(receipt, GrantSignatureEd25519, signature); err != nil {
		t.Fatalf("VerifyEffectCloseReceiptSignature(): %v", err)
	}
	wrongKernelVerifier, err := NewEd25519GrantSignatureVerifier(
		kernelSigner.PublicKeyBytes(), "kms://helm/approval-other", receipt.KernelTrustRootID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongKernelVerifier.VerifyEffectCloseReceiptSignature(receipt, GrantSignatureEd25519, signature); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("wrong Kernel close trust metadata error = %v", err)
	}
	if err := kernelVerifier.VerifyDispatchAdmissionSignature(
		contracts.ApprovalDispatchAdmission{}, GrantSignatureEd25519, signature,
	); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("cross-contract signature error = %v", err)
	}

	deadline := now.Add(2 * time.Hour)
	acknowledgementV2 := effectCloseSignatureAcknowledgementV2(t, now, &deadline)
	envelopeV2, err := SignConnectorEffectAcknowledgementV2(acknowledgementV2, connectorSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyEnvelopeV2(envelopeV2); err != nil {
		t.Fatalf("VerifyEnvelopeV2(): %v", err)
	}
	payloadV1, err := ConnectorEffectAcknowledgementSigningPayload(acknowledgement)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(connectorSigner.PublicKeyBytes(), payloadV1, mustDecodeHex(t, envelopeV2.Signature)) {
		t.Fatal("v2 acknowledgement signature verified against v1 payload")
	}
	payloadV2, err := ConnectorEffectAcknowledgementV2SigningPayload(acknowledgementV2)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(connectorSigner.PublicKeyBytes(), payloadV2, mustDecodeHex(t, envelope.Signature)) {
		t.Fatal("v1 acknowledgement signature verified against v2 payload")
	}

	receiptV2 := effectCloseSignatureReceiptV2(t, acknowledgementV2, now.Add(2*time.Second))
	signatureV2, err := SignEffectCloseReceiptV2(receiptV2, kernelSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := kernelVerifier.VerifyEffectCloseReceiptV2Signature(receiptV2, GrantSignatureEd25519, signatureV2); err != nil {
		t.Fatalf("VerifyEffectCloseReceiptV2Signature(): %v", err)
	}
	receiptPayloadV1, err := EffectCloseReceiptSigningPayload(receipt, GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(kernelSigner.PublicKeyBytes(), receiptPayloadV1, mustDecodeHex(t, signatureV2)) {
		t.Fatal("v2 close signature verified against v1 receipt payload")
	}
	receiptPayloadV2, err := EffectCloseReceiptV2SigningPayload(receiptV2, GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(kernelSigner.PublicKeyBytes(), receiptPayloadV2, mustDecodeHex(t, signature)) {
		t.Fatal("v1 close signature verified against v2 receipt payload")
	}
}

func effectCloseSignatureAcknowledgement(t *testing.T, now time.Time) contracts.ConnectorEffectAcknowledgement {
	t.Helper()
	acknowledgement, err := (contracts.ConnectorEffectAcknowledgement{
		SchemaVersion:     contracts.ConnectorEffectAcknowledgementSchemaV1,
		ContractVersion:   contracts.ConnectorEffectAcknowledgementContractV1,
		AcknowledgementID: "ack-a", AdmissionID: "admission-a", AttemptID: "attempt-a",
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "packs.lifecycle",
		ConnectorID: "github", ConnectorVersion: "1.0.0", ConnectorAction: "github.create_issue",
		ConnectorExecutionRef: "github-request-a", ProofSessionRef: "proof-a", IntentRef: "intent-a",
		IdempotencyKeyHash: shaRef("1"), EffectHash: shaRef("2"),
		Outcome: contracts.ConnectorEffectOutcomeApplied, ResponseHash: shaRef("3"), EffectRef: "github-issue-42",
		IssuerID: "publisher-a", SigningKeyRef: "kms://connector/ack-a",
		Algorithm: contracts.ConnectorEffectAcknowledgementAlgorithm, ObservedAt: now,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return acknowledgement
}

func effectCloseSignatureReceipt(
	t *testing.T,
	acknowledgement contracts.ConnectorEffectAcknowledgement,
	closedAt time.Time,
) contracts.EffectCloseReceipt {
	t.Helper()
	receipt, err := (contracts.EffectCloseReceipt{
		SchemaVersion: contracts.EffectCloseReceiptSchemaV1, ContractVersion: contracts.EffectCloseReceiptContractV1,
		CloseID: "effect-close-a", State: contracts.EffectCloseReceiptStateClosed,
		AdmissionID: acknowledgement.AdmissionID, AttemptID: acknowledgement.AttemptID,
		TenantID: acknowledgement.TenantID, WorkspaceID: acknowledgement.WorkspaceID, Audience: acknowledgement.Audience,
		ConnectorID: acknowledgement.ConnectorID, ConnectorVersion: acknowledgement.ConnectorVersion,
		ConnectorAction: acknowledgement.ConnectorAction,
		PriorState:      contracts.EffectClosePriorStateStarted, ReservationSequence: 2,
		ReservationHeadHash: shaRef("4"), AcknowledgementHash: acknowledgement.AcknowledgementHash,
		Outcome: acknowledgement.Outcome, IdempotencyKeyHash: acknowledgement.IdempotencyKeyHash,
		EffectHash: acknowledgement.EffectHash, ResponseHash: acknowledgement.ResponseHash,
		ConnectorExecutionRef: acknowledgement.ConnectorExecutionRef,
		ProofSessionRef:       acknowledgement.ProofSessionRef, IntentRef: acknowledgement.IntentRef,
		EffectRef:       acknowledgement.EffectRef,
		EvidencePackRef: "evidence-pack-a", EvidencePackHash: shaRef("5"),
		KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/approval-a",
		ClosedBy: "spiffe://helm/data-plane-a", ClosedAt: closedAt,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func effectCloseSignatureAcknowledgementV2(
	t *testing.T,
	now time.Time,
	deadline *time.Time,
) contracts.ConnectorEffectAcknowledgementV2 {
	t.Helper()
	acknowledgement, err := (contracts.ConnectorEffectAcknowledgementV2{
		SchemaVersion:     contracts.ConnectorEffectAcknowledgementSchemaV2,
		ContractVersion:   contracts.ConnectorEffectAcknowledgementContractV2,
		AcknowledgementID: "ack-v2", AdmissionID: "admission-v2", AttemptID: "attempt-v2",
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "packs.lifecycle",
		ConnectorID: "github", ConnectorVersion: "1.0.0", ConnectorAction: "github.create_issue",
		ConnectorExecutionRef: "github-request-v2", AdapterID: "adapter.github-app", AdapterVersion: "2026.09.04",
		AdapterCapabilityRef: "capability:github.issue.create", AdapterCapabilityHash: shaRef("c"),
		ProofSessionRef: "proof-v2", IntentRef: "intent-v2", ActivationRecordRef: "activation-record-v2",
		ActivationRecordHash: shaRef("6"), IdempotencyKeyHash: shaRef("7"), EffectHash: shaRef("8"),
		Outcome: contracts.ConnectorEffectOutcomeApplied, ResponseHash: shaRef("9"), EffectRef: "github-issue-77",
		ReconciliationRef: "reconciliation-v2",
		Finality: &contracts.EffectCloseFinalityV2{
			ExpectedFinalityPredicateRef:  "predicate:github.issue.created",
			ExpectedFinalityPredicateHash: shaRef("d"),
			ObservedExternalFacts: []contracts.EffectCloseObservedExternalFactV2{
				{Ref: "fact:delivery", Hash: shaRef("e")},
				{Ref: "fact:webhook", Hash: shaRef("f")},
			},
			ReconciliationDeadline: *deadline, ResolutionRef: "resolution-v2",
			ResolutionState:            contracts.EffectCloseResolutionStateCompensated,
			ConditionalCompensationRef: "compensation-v2",
		},
		IssuerID: "publisher-a", SigningKeyRef: "kms://connector/ack-a",
		Algorithm: contracts.ConnectorEffectAcknowledgementAlgorithm, ObservedAt: now,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return acknowledgement
}

func effectCloseSignatureReceiptV2(
	t *testing.T,
	acknowledgement contracts.ConnectorEffectAcknowledgementV2,
	closedAt time.Time,
) contracts.EffectCloseReceiptV2 {
	t.Helper()
	receipt, err := (contracts.EffectCloseReceiptV2{
		SchemaVersion: contracts.EffectCloseReceiptSchemaV2, ContractVersion: contracts.EffectCloseReceiptContractV2,
		CloseID: "effect-close-v2", State: contracts.EffectCloseReceiptStateClosed,
		AdmissionID: acknowledgement.AdmissionID, AttemptID: acknowledgement.AttemptID,
		TenantID: acknowledgement.TenantID, WorkspaceID: acknowledgement.WorkspaceID, Audience: acknowledgement.Audience,
		ConnectorID: acknowledgement.ConnectorID, ConnectorVersion: acknowledgement.ConnectorVersion,
		ConnectorAction: acknowledgement.ConnectorAction, AdapterID: acknowledgement.AdapterID, AdapterVersion: acknowledgement.AdapterVersion,
		AdapterCapabilityRef: acknowledgement.AdapterCapabilityRef, AdapterCapabilityHash: acknowledgement.AdapterCapabilityHash,
		PriorState: contracts.EffectClosePriorStateStarted, ReservationSequence: 2,
		ReservationHeadHash: shaRef("a"), AcknowledgementHash: acknowledgement.AcknowledgementHash,
		ActivationRecordRef: acknowledgement.ActivationRecordRef, ActivationRecordHash: acknowledgement.ActivationRecordHash,
		IdempotencyKeyHash: acknowledgement.IdempotencyKeyHash, EffectHash: acknowledgement.EffectHash,
		Outcome: acknowledgement.Outcome, ResponseHash: acknowledgement.ResponseHash,
		ConnectorExecutionRef: acknowledgement.ConnectorExecutionRef, ProofSessionRef: acknowledgement.ProofSessionRef,
		IntentRef: acknowledgement.IntentRef, EffectRef: acknowledgement.EffectRef, ReconciliationRef: acknowledgement.ReconciliationRef,
		Finality: acknowledgement.Finality, EvidencePackRef: "evidence-pack-v2", EvidencePackHash: shaRef("b"),
		KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/approval-a",
		ClosedBy: "spiffe://helm/data-plane-a", ClosedAt: closedAt,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
