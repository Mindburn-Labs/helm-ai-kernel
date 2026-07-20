package approvalceremony

// quantum_posture: tests the classical Ed25519 effect-disposition command and
// receipt signing; no post-quantum claim.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestEffectDispositionSignaturesUsePinnedIndependentAuthorities(t *testing.T) {
	now := time.Date(2026, 7, 18, 16, 17, 18, 123456000, time.UTC)
	command := effectDispositionSignatureCommand(t, now)
	controlSigner := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, ed25519.SeedSize)), "control-disposition-a",
	)
	envelope, err := SignEffectDispositionCommand(command, controlSigner)
	if err != nil {
		t.Fatal(err)
	}
	trustedKey := TrustedEffectDispositionCommandKey{
		AuthorityID: command.AuthorityID, SigningKeyRef: command.SigningKeyRef, Audience: command.Audience,
		PublicKey: controlSigner.PublicKeyBytes(), Enabled: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}
	verifier, err := NewEd25519EffectDispositionCommandVerifier([]TrustedEffectDispositionCommandKey{trustedKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyEnvelope(envelope); err != nil {
		t.Fatalf("VerifyEnvelope(): %v", err)
	}
	mutated := envelope
	mutated.Command.Action = contracts.EffectDispositionActionRequestCompensate
	if err := verifier.VerifyEnvelope(mutated); !errors.Is(err, ErrEffectDispositionCommandRejected) {
		t.Fatalf("mutated command error = %v", err)
	}
	disabledKey := trustedKey
	disabledKey.Enabled = false
	disabledVerifier, err := NewEd25519EffectDispositionCommandVerifier([]TrustedEffectDispositionCommandKey{disabledKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := disabledVerifier.VerifyEnvelope(envelope); !errors.Is(err, ErrEffectDispositionCommandRejected) {
		t.Fatalf("disabled key error = %v", err)
	}
	if err := disabledVerifier.VerifyStoredEnvelope(envelope); err != nil {
		t.Fatalf("VerifyStoredEnvelope() with a disabled-after-issue key = %v, want nil", err)
	}
	if err := disabledVerifier.VerifyStoredEnvelope(mutated); !errors.Is(err, ErrEffectDispositionCommandRejected) {
		t.Fatalf("VerifyStoredEnvelope() with a tampered command = %v, want rejected", err)
	}
	futureKey := trustedKey
	futureKey.NotBefore = now.Add(time.Second)
	futureVerifier, err := NewEd25519EffectDispositionCommandVerifier([]TrustedEffectDispositionCommandKey{futureKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := futureVerifier.VerifyEnvelope(envelope); !errors.Is(err, ErrEffectDispositionCommandRejected) {
		t.Fatalf("future key error = %v", err)
	}
	if _, err := NewEd25519EffectDispositionCommandVerifier([]TrustedEffectDispositionCommandKey{trustedKey, trustedKey}); !errors.Is(err, ErrEffectDispositionCommandRejected) {
		t.Fatalf("duplicate key error = %v", err)
	}

	kernelSigner := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{82}, ed25519.SeedSize)), "kernel-disposition-a",
	)
	receipt := effectDispositionSignatureReceipt(t, command, now.Add(time.Second))
	signature, err := SignEffectDispositionReceipt(receipt, kernelSigner)
	if err != nil {
		t.Fatal(err)
	}
	kernelVerifier, err := NewEd25519GrantSignatureVerifier(
		kernelSigner.PublicKeyBytes(), receipt.SigningKeyRef, receipt.KernelTrustRootID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := kernelVerifier.VerifyEffectDispositionReceiptSignature(receipt, GrantSignatureEd25519, signature); err != nil {
		t.Fatalf("VerifyEffectDispositionReceiptSignature(): %v", err)
	}
	if err := kernelVerifier.VerifyEffectCloseReceiptSignature(contracts.EffectCloseReceipt{}, GrantSignatureEd25519, signature); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("cross-domain signature error = %v", err)
	}
}

func effectDispositionSignatureCommand(t *testing.T, now time.Time) contracts.EffectDispositionCommand {
	t.Helper()
	command, err := (contracts.EffectDispositionCommand{
		SchemaVersion:   contracts.EffectDispositionCommandSchemaV1,
		ContractVersion: contracts.EffectDispositionCommandContractV1,
		CommandID:       "effect-disposition-a", DispositionSequence: 1,
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "packs.lifecycle",
		FenceCommandID: "fence-a", FenceCommandHash: shaRef("1"), FenceEpoch: 1, FenceReceiptHash: shaRef("2"),
		AdmissionID: "admission-a", AttemptID: "attempt-a", ReservationSequence: 3,
		ReservationHeadHash: shaRef("3"), ReservationState: string(EffectReservationStateUncertain),
		ConnectorID: "github", ConnectorVersion: "1.0.0", ConnectorAction: "github.create_issue",
		ConnectorExecutionRef: "github-request-a", ProofSessionRef: "proof-a", IntentRef: "intent-a",
		EffectRef: "github-issue-42", IdempotencyKeyHash: shaRef("4"), EffectHash: shaRef("5"),
		Action: contracts.EffectDispositionActionReconcileSource, DispositionRef: "disposition-workflow-a",
		ActorID: "operator-a", Reason: "reconcile active work",
		AuthorityID: "spiffe://helm/control-plane", SigningKeyRef: "kms://helm/control-plane/disposition-a",
		Algorithm: contracts.EffectDispositionAlgorithmV1, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func effectDispositionSignatureReceipt(
	t *testing.T,
	command contracts.EffectDispositionCommand,
	acceptedAt time.Time,
) contracts.EffectDispositionReceipt {
	t.Helper()
	receipt, err := (contracts.EffectDispositionReceipt{
		SchemaVersion:   contracts.EffectDispositionReceiptSchemaV1,
		ContractVersion: contracts.EffectDispositionReceiptContractV1,
		ReceiptID:       "effect-disposition-receipt-a", State: contracts.EffectDispositionReceiptStateAccepted,
		ExecutionAuthority: contracts.EffectDispositionExecutionAuthorityNone,
		CommandID:          command.CommandID, CommandHash: command.CommandHash,
		DispositionSequence: command.DispositionSequence, PreviousReceiptHash: command.PreviousReceiptHash,
		TenantID: command.TenantID, WorkspaceID: command.WorkspaceID, Audience: command.Audience,
		FenceCommandID: command.FenceCommandID, FenceCommandHash: command.FenceCommandHash,
		FenceEpoch: command.FenceEpoch, FenceReceiptHash: command.FenceReceiptHash,
		AdmissionID: command.AdmissionID, ReservationSequence: command.ReservationSequence,
		ReservationHeadHash: command.ReservationHeadHash, ReservationState: command.ReservationState,
		Action: command.Action, DispositionRef: command.DispositionRef,
		KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/approval-a",
		AcceptedBy: "spiffe://helm/kernel-a", AcceptedAt: acceptedAt,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
