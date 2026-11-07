package approvalceremony

// quantum_posture: tests the classical Ed25519 connector effect-close
// acknowledgement and receipt signing; no post-quantum claim.

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

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
