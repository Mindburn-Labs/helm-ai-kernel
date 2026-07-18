package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestConnectorEffectAcknowledgementAndCloseReceiptIntegrity(t *testing.T) {
	now := time.Date(2026, 7, 18, 10, 11, 12, 123456000, time.UTC)
	acknowledgement, err := (ConnectorEffectAcknowledgement{
		SchemaVersion: ConnectorEffectAcknowledgementSchemaV1, ContractVersion: ConnectorEffectAcknowledgementContractV1,
		AcknowledgementID: "ack-a", AdmissionID: "admission-a", AttemptID: "attempt-a",
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "packs.lifecycle",
		ConnectorID: "github", ConnectorVersion: "1.0.0", ConnectorAction: "github.create_issue",
		ConnectorExecutionRef: "github-request-a", ProofSessionRef: "proof-a", IntentRef: "intent-a",
		IdempotencyKeyHash: effectCloseTestSHA("idempotency"), EffectHash: effectCloseTestSHA("effect"),
		Outcome: ConnectorEffectOutcomeApplied, ResponseHash: effectCloseTestSHA("response"), EffectRef: "github-issue-42",
		ReconciliationRef: "reconciliation-a", IssuerID: "publisher-a", SigningKeyRef: "kms://connector/ack-a",
		Algorithm: ConnectorEffectAcknowledgementAlgorithm, ObservedAt: now,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := acknowledgement.ValidateIntegrity(); err != nil {
		t.Fatalf("ValidateIntegrity(): %v", err)
	}
	receipt, err := (EffectCloseReceipt{
		SchemaVersion: EffectCloseReceiptSchemaV1, ContractVersion: EffectCloseReceiptContractV1,
		CloseID: "effect-close-a", State: EffectCloseReceiptStateClosed,
		AdmissionID: acknowledgement.AdmissionID, AttemptID: acknowledgement.AttemptID,
		TenantID: acknowledgement.TenantID, WorkspaceID: acknowledgement.WorkspaceID, Audience: acknowledgement.Audience,
		ConnectorID: acknowledgement.ConnectorID, ConnectorVersion: acknowledgement.ConnectorVersion,
		ConnectorAction: acknowledgement.ConnectorAction,
		PriorState:      EffectClosePriorStateUncertain, ReservationSequence: 3,
		ReservationHeadHash: effectCloseTestSHA("head"), AcknowledgementHash: acknowledgement.AcknowledgementHash,
		Outcome: acknowledgement.Outcome, IdempotencyKeyHash: acknowledgement.IdempotencyKeyHash,
		EffectHash: acknowledgement.EffectHash, ResponseHash: acknowledgement.ResponseHash,
		ConnectorExecutionRef: acknowledgement.ConnectorExecutionRef,
		ProofSessionRef:       acknowledgement.ProofSessionRef, IntentRef: acknowledgement.IntentRef,
		EffectRef: acknowledgement.EffectRef, ReconciliationRef: acknowledgement.ReconciliationRef,
		EvidencePackRef: "evidence-pack-a", EvidencePackHash: effectCloseTestSHA("evidence-pack"),
		KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/approval-a",
		ClosedBy: "spiffe://helm/data-plane-a", ClosedAt: now.Add(time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.ValidateAcknowledgement(acknowledgement); err != nil {
		t.Fatalf("ValidateAcknowledgement(): %v", err)
	}

	mutatedAcknowledgement := acknowledgement
	mutatedAcknowledgement.ResponseHash = effectCloseTestSHA("other-response")
	if err := mutatedAcknowledgement.ValidateIntegrity(); !errors.Is(err, ErrConnectorEffectAcknowledgementInvalid) {
		t.Fatalf("mutated acknowledgement error = %v", err)
	}
	mutatedReceipt := receipt
	mutatedReceipt.EvidencePackHash = effectCloseTestSHA("other-pack")
	if err := mutatedReceipt.ValidateIntegrity(); !errors.Is(err, ErrEffectCloseReceiptInvalid) {
		t.Fatalf("mutated receipt error = %v", err)
	}
	missingReconciliation := receipt
	missingReconciliation.ReceiptHash = ""
	missingReconciliation.ReconciliationRef = ""
	if _, err := missingReconciliation.Seal(); !errors.Is(err, ErrEffectCloseReceiptInvalid) {
		t.Fatalf("missing reconciliation error = %v", err)
	}
	notApplied := acknowledgement
	notApplied.AcknowledgementHash = ""
	notApplied.Outcome = ConnectorEffectOutcomeNotApplied
	if _, err := notApplied.Seal(); !errors.Is(err, ErrConnectorEffectAcknowledgementInvalid) {
		t.Fatalf("NOT_APPLIED effect_ref error = %v", err)
	}
}

func TestConnectorEffectAcknowledgementEnvelopeRejectsNonCanonicalSignature(t *testing.T) {
	now := time.Date(2026, 7, 18, 10, 11, 12, 0, time.UTC)
	acknowledgement, err := (ConnectorEffectAcknowledgement{
		SchemaVersion: ConnectorEffectAcknowledgementSchemaV1, ContractVersion: ConnectorEffectAcknowledgementContractV1,
		AcknowledgementID: "ack-a", AdmissionID: "admission-a", AttemptID: "attempt-a",
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "packs.lifecycle",
		ConnectorID: "github", ConnectorVersion: "1.0.0", ConnectorAction: "github.create_issue",
		ConnectorExecutionRef: "github-request-a", IntentRef: "intent-a",
		IdempotencyKeyHash: effectCloseTestSHA("idempotency"), EffectHash: effectCloseTestSHA("effect"),
		Outcome: ConnectorEffectOutcomeNotApplied, ResponseHash: effectCloseTestSHA("response"),
		IssuerID: "publisher-a", SigningKeyRef: "kms://connector/ack-a",
		Algorithm: ConnectorEffectAcknowledgementAlgorithm, ObservedAt: now,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	envelope := ConnectorEffectAcknowledgementEnvelope{Acknowledgement: acknowledgement, Signature: "AA"}
	if err := envelope.Validate(); !errors.Is(err, ErrConnectorEffectAcknowledgementInvalid) {
		t.Fatalf("non-canonical signature error = %v", err)
	}
}

func effectCloseTestSHA(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
