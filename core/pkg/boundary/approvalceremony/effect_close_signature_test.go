package approvalceremony

// quantum_posture: tests the classical Ed25519 connector effect-close
// acknowledgement and receipt signing; no post-quantum claim.

import (
	"bytes"
	"crypto/ed25519"
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
