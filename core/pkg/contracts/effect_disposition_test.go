package contracts

import (
	"errors"
	"testing"
	"time"
)

func TestEffectDispositionCommandAndReceiptIntegrity(t *testing.T) {
	now := time.Date(2026, 7, 18, 14, 15, 16, 123456000, time.UTC)
	command := effectDispositionCommandFixture(t, now)
	if err := command.ValidateIntegrity(); err != nil {
		t.Fatal(err)
	}
	receipt, err := (EffectDispositionReceipt{
		SchemaVersion: EffectDispositionReceiptSchemaV1, ContractVersion: EffectDispositionReceiptContractV1,
		ReceiptID: "effect-disposition-receipt-a", State: EffectDispositionReceiptStateAccepted,
		ExecutionAuthority: EffectDispositionExecutionAuthorityNone,
		CommandID:          command.CommandID, CommandHash: command.CommandHash,
		DispositionSequence: command.DispositionSequence, PreviousReceiptHash: command.PreviousReceiptHash,
		TenantID: command.TenantID, WorkspaceID: command.WorkspaceID, Audience: command.Audience,
		FenceCommandID: command.FenceCommandID, FenceCommandHash: command.FenceCommandHash,
		FenceEpoch: command.FenceEpoch, FenceReceiptHash: command.FenceReceiptHash,
		AdmissionID: command.AdmissionID, ReservationSequence: command.ReservationSequence,
		ReservationHeadHash: command.ReservationHeadHash, ReservationState: command.ReservationState,
		Action: command.Action, DispositionRef: command.DispositionRef,
		KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/approval-a",
		AcceptedBy: "spiffe://helm/kernel-a", AcceptedAt: now.Add(time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.ValidateCommand(command); err != nil {
		t.Fatal(err)
	}

	mutatedCommand := command
	mutatedCommand.Reason = "different"
	if err := mutatedCommand.ValidateIntegrity(); !errors.Is(err, ErrEffectDispositionCommandInvalid) {
		t.Fatalf("mutated command error = %v", err)
	}
	mutatedReceipt := receipt
	mutatedReceipt.ExecutionAuthority = "CANCEL"
	if err := mutatedReceipt.ValidateIntegrity(); !errors.Is(err, ErrEffectDispositionReceiptInvalid) {
		t.Fatalf("mutated authority error = %v", err)
	}
	otherCommand := command
	otherCommand.DispositionRef = "disposition-other"
	otherCommand.CommandHash = ""
	otherCommand, err = otherCommand.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.ValidateCommand(otherCommand); !errors.Is(err, ErrEffectDispositionReceiptInvalid) {
		t.Fatalf("cross-command receipt error = %v", err)
	}
}

func TestEffectDispositionCommandRejectsUnsafeShapes(t *testing.T) {
	now := time.Date(2026, 7, 18, 14, 15, 16, 0, time.UTC)
	tests := map[string]func(*EffectDispositionCommand){
		"unsupported action":   func(c *EffectDispositionCommand) { c.Action = "EXECUTE_CANCEL" },
		"terminal reservation": func(c *EffectDispositionCommand) { c.ReservationState = EffectCloseReceiptStateClosed },
		"unsafe sequence":      func(c *EffectDispositionCommand) { c.DispositionSequence = ConnectorReleaseAuthorityMaxRevision + 1 },
		"long lifetime": func(c *EffectDispositionCommand) {
			c.ExpiresAt = c.IssuedAt.Add(EffectDispositionMaxCommandLifetime + time.Microsecond)
		},
		"first with predecessor": func(c *EffectDispositionCommand) { c.PreviousReceiptHash = dispositionSHA("f") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			command := effectDispositionCommandFixture(t, now)
			command.CommandHash = ""
			mutate(&command)
			if _, err := command.Seal(); !errors.Is(err, ErrEffectDispositionCommandInvalid) {
				t.Fatalf("Seal() error = %v", err)
			}
		})
	}
}

func effectDispositionCommandFixture(t *testing.T, now time.Time) EffectDispositionCommand {
	t.Helper()
	command, err := (EffectDispositionCommand{
		SchemaVersion: EffectDispositionCommandSchemaV1, ContractVersion: EffectDispositionCommandContractV1,
		CommandID: "effect-disposition-a", DispositionSequence: 1,
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "packs.lifecycle",
		FenceCommandID: "fence-a", FenceCommandHash: dispositionSHA("1"), FenceEpoch: 1,
		FenceReceiptHash: dispositionSHA("2"), AdmissionID: "admission-a", AttemptID: "attempt-a",
		ReservationSequence: 3, ReservationHeadHash: dispositionSHA("3"), ReservationState: EffectClosePriorStateUncertain,
		ConnectorID: "github", ConnectorVersion: "1.0.0", ConnectorAction: "github.create_issue",
		ConnectorExecutionRef: "github-request-a", ProofSessionRef: "proof-a", IntentRef: "intent-a",
		EffectRef: "github-issue-42", IdempotencyKeyHash: dispositionSHA("4"), EffectHash: dispositionSHA("5"),
		Action: EffectDispositionActionReconcileSource, DispositionRef: "disposition-workflow-a",
		ActorID: "operator-a", Reason: "reconcile active work after emergency stop",
		AuthorityID: "spiffe://helm/control-plane", SigningKeyRef: "kms://helm/control-plane/disposition-a",
		Algorithm: EffectDispositionAlgorithmV1, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func dispositionSHA(fill string) string {
	return "sha256:" + repeatHex(fill)
}
