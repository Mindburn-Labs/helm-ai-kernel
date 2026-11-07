package approvalceremony

// quantum_posture: tests the classical Ed25519 effect-disposition command and
// receipt signing; no post-quantum claim.

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

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
