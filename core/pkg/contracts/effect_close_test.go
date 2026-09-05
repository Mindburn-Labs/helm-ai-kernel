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

func TestConnectorEffectAcknowledgementV2AndCloseReceiptV2Integrity(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 11, 12, 123456000, time.UTC)
	deadline := now.Add(2 * time.Hour)
	acknowledgement, err := (ConnectorEffectAcknowledgementV2{
		SchemaVersion: ConnectorEffectAcknowledgementSchemaV2, ContractVersion: ConnectorEffectAcknowledgementContractV2,
		AcknowledgementID: "ack-v2", AdmissionID: "admission-v2", AttemptID: "attempt-v2",
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "packs.lifecycle",
		ConnectorID: "github", ConnectorVersion: "1.2.3", ConnectorAction: "github.create_issue",
		ConnectorExecutionRef: "github-request-v2", AdapterID: "adapter.github-app", AdapterVersion: "2026.09.04",
		AdapterCapabilityRef: "capability:github.issue.create", AdapterCapabilityHash: effectCloseTestSHA("adapter-capability"),
		IntentRef: "intent-v2", ActivationRecordRef: "activation-record-v2", ActivationRecordHash: effectCloseTestSHA("activation"),
		IdempotencyKeyHash: effectCloseTestSHA("idempotency-v2"), EffectHash: effectCloseTestSHA("effect-v2"),
		Outcome: ConnectorEffectOutcomeApplied, ResponseHash: effectCloseTestSHA("response-v2"), EffectRef: "github-issue-77",
		ReconciliationRef: "reconciliation-v2",
		Finality: &EffectCloseFinalityV2{
			ExpectedFinalityPredicateRef:  "predicate:github.issue.created",
			ExpectedFinalityPredicateHash: effectCloseTestSHA("predicate-v2"),
			ObservedExternalFacts: []EffectCloseObservedExternalFactV2{
				{Ref: "fact:delivery", Hash: effectCloseTestSHA("fact-delivery")},
				{Ref: "fact:webhook", Hash: effectCloseTestSHA("fact-webhook")},
			},
			ReconciliationDeadline:     deadline,
			ResolutionRef:              "resolution-v2",
			ResolutionState:            EffectCloseResolutionStateCompensated,
			ConditionalCompensationRef: "compensation-v2",
		},
		IssuerID: "publisher-v2", SigningKeyRef: "kms://connector/ack-v2",
		Algorithm: ConnectorEffectAcknowledgementAlgorithm, ObservedAt: now,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := acknowledgement.ValidateIntegrity(); err != nil {
		t.Fatalf("ValidateIntegrity(): %v", err)
	}
	receipt, err := (EffectCloseReceiptV2{
		SchemaVersion: EffectCloseReceiptSchemaV2, ContractVersion: EffectCloseReceiptContractV2,
		CloseID: "effect-close-v2", State: EffectCloseReceiptStateClosed,
		AdmissionID: acknowledgement.AdmissionID, AttemptID: acknowledgement.AttemptID,
		TenantID: acknowledgement.TenantID, WorkspaceID: acknowledgement.WorkspaceID, Audience: acknowledgement.Audience,
		ConnectorID: acknowledgement.ConnectorID, ConnectorVersion: acknowledgement.ConnectorVersion,
		ConnectorAction: acknowledgement.ConnectorAction, AdapterID: acknowledgement.AdapterID, AdapterVersion: acknowledgement.AdapterVersion,
		AdapterCapabilityRef: acknowledgement.AdapterCapabilityRef, AdapterCapabilityHash: acknowledgement.AdapterCapabilityHash,
		PriorState: EffectClosePriorStateUncertain, ReservationSequence: 7, ReservationHeadHash: effectCloseTestSHA("head-v2"),
		AcknowledgementHash: acknowledgement.AcknowledgementHash, ActivationRecordRef: acknowledgement.ActivationRecordRef,
		ActivationRecordHash: acknowledgement.ActivationRecordHash, IdempotencyKeyHash: acknowledgement.IdempotencyKeyHash,
		EffectHash: acknowledgement.EffectHash, Outcome: acknowledgement.Outcome, ResponseHash: acknowledgement.ResponseHash,
		ConnectorExecutionRef: acknowledgement.ConnectorExecutionRef, IntentRef: acknowledgement.IntentRef,
		EffectRef: acknowledgement.EffectRef, ReconciliationRef: acknowledgement.ReconciliationRef, Finality: acknowledgement.Finality,
		EvidencePackRef: "evidence-pack-v2", EvidencePackHash: effectCloseTestSHA("evidence-pack-v2"),
		KernelTrustRootID: "kernel-root-v2", SigningKeyRef: "kms://helm/approval-v2",
		ClosedBy: "spiffe://helm/data-plane-v2", ClosedAt: now.Add(time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.ValidateAcknowledgement(acknowledgement); err != nil {
		t.Fatalf("ValidateAcknowledgement(): %v", err)
	}

	unsortedFacts := acknowledgement
	unsortedFacts.AcknowledgementHash = ""
	unsortedFacts.Finality = &EffectCloseFinalityV2{
		ExpectedFinalityPredicateRef:  "predicate:github.issue.created",
		ExpectedFinalityPredicateHash: effectCloseTestSHA("predicate-v2"),
		ObservedExternalFacts: []EffectCloseObservedExternalFactV2{
			{Ref: "fact:webhook", Hash: effectCloseTestSHA("fact-webhook")},
			{Ref: "fact:delivery", Hash: effectCloseTestSHA("fact-delivery")},
		},
		ReconciliationDeadline: deadline,
		ResolutionRef:          "resolution-v2",
		ResolutionState:        EffectCloseResolutionStateSuccess,
	}
	if _, err := unsortedFacts.Seal(); !errors.Is(err, ErrConnectorEffectAcknowledgementInvalid) {
		t.Fatalf("unsorted observed_external_facts error = %v", err)
	}

	missingDeadline := acknowledgement
	missingDeadline.AcknowledgementHash = ""
	missingDeadline.Finality = &EffectCloseFinalityV2{
		ExpectedFinalityPredicateRef:  "predicate:github.issue.created",
		ExpectedFinalityPredicateHash: effectCloseTestSHA("predicate-v2"),
		ObservedExternalFacts: []EffectCloseObservedExternalFactV2{
			{Ref: "fact:delivery", Hash: effectCloseTestSHA("fact-delivery")},
		},
		ResolutionRef:              "resolution-v2",
		ResolutionState:            EffectCloseResolutionStateCompensated,
		ConditionalCompensationRef: "compensation-v2",
	}
	if _, err := missingDeadline.Seal(); !errors.Is(err, ErrConnectorEffectAcknowledgementInvalid) {
		t.Fatalf("missing reconciliation_deadline error = %v", err)
	}

	mismatchedOutcome := acknowledgement
	mismatchedOutcome.AcknowledgementHash = ""
	mismatchedOutcome.Outcome = ConnectorEffectOutcomeNotApplied
	if _, err := mismatchedOutcome.Seal(); !errors.Is(err, ErrConnectorEffectAcknowledgementInvalid) {
		t.Fatalf("resolution_state to outcome mismatch error = %v", err)
	}

	mutatedReceipt := receipt
	mutatedReceipt.ActivationRecordHash = effectCloseTestSHA("other-activation")
	if err := mutatedReceipt.ValidateIntegrity(); !errors.Is(err, ErrEffectCloseReceiptInvalid) {
		t.Fatalf("tampered activation hash integrity error = %v", err)
	}

	legacy := ConnectorEffectAcknowledgement{
		SchemaVersion:   acknowledgement.SchemaVersion,
		ContractVersion: acknowledgement.ContractVersion,
		Algorithm:       acknowledgement.Algorithm,
	}
	if err := legacy.Validate(); !errors.Is(err, ErrConnectorEffectAcknowledgementInvalid) {
		t.Fatalf("v2 acknowledgement reached v1 validator: %v", err)
	}
}

func effectCloseTestSHA(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
