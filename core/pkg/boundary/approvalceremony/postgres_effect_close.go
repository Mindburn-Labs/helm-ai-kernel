package approvalceremony

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	connectorregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry/connectors"
)

const effectClosureColumns = `
tenant_id, workspace_id, admission_id, close_id,
acknowledgement_hash, receipt_hash, outcome,
evidence_pack_ref, evidence_pack_hash,
acknowledgement_json, receipt_json,
signature_algorithm, signature, created_at
`

func (s *PostgresStore) closeEffectReservation(
	ctx context.Context,
	identity ConsumerIdentity,
	request EffectCloseRequest,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
	acknowledgementVerifier EffectAcknowledgementVerifier,
	dispositionVerifier EffectDispositionCommandVerifier,
	signer crypto.Signer,
) (EffectClosureRecord, error) {
	if s == nil || s.db == nil || s.grantVerifier == nil || releaseAuthorities == nil ||
		acknowledgementVerifier == nil || dispositionVerifier == nil || signer == nil {
		return EffectClosureRecord{}, errors.New("effect close store is not configured")
	}
	if err := request.Validate(); err != nil {
		return EffectClosureRecord{}, err
	}
	// The acknowledgement signature is verified per reservation state below:
	// a genuinely new close requires an enabled key (VerifyEnvelope), while an
	// already-COMPLETED replay tolerates a since-disabled key
	// (VerifyStoredEnvelope), so idempotent retries survive a key rotation.
	if err := acknowledgementVerifier.VerifyStoredEnvelope(request.Acknowledgement); err != nil {
		return EffectClosureRecord{}, err
	}
	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return EffectClosureRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockApprovalScope(ctx, tx, identity.TenantID, identity.WorkspaceID); err != nil {
		return EffectClosureRecord{}, err
	}

	current, err := queryCurrentEffectReservation(ctx, tx, identity.TenantID, identity.WorkspaceID, request.AdmissionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EffectClosureRecord{}, ErrNotFound
		}
		return EffectClosureRecord{}, err
	}
	if err := exactEffectReservationIdentity(current, identity); err != nil {
		return EffectClosureRecord{}, err
	}
	if err := s.verifyEffectReservationAuthorities(current, releaseAuthorities); err != nil {
		return EffectClosureRecord{}, err
	}
	if current.State == EffectReservationStateCompleted {
		existing, err := queryEffectClosureRecord(ctx, tx, identity.TenantID, identity.WorkspaceID, request.AdmissionID)
		if err != nil {
			return EffectClosureRecord{}, err
		}
		if err := s.verifyEffectClosureRecord(
			ctx, tx, current, existing, releaseAuthorities, acknowledgementVerifier, dispositionVerifier,
		); err != nil {
			return EffectClosureRecord{}, err
		}
		if !effectCloseRequestMatchesRecord(request, existing) {
			return EffectClosureRecord{}, ErrEffectCloseConflict
		}
		if err := tx.Commit(); err != nil {
			return EffectClosureRecord{}, fmt.Errorf("commit effect close replay: %w", err)
		}
		return existing, nil
	}
	if current.State != EffectReservationStateStarted && current.State != EffectReservationStateUncertain {
		return EffectClosureRecord{}, ErrEffectCloseTerminal
	}

	// A genuinely new close must be signed by a currently enabled key.
	if err := acknowledgementVerifier.VerifyEnvelope(request.Acknowledgement); err != nil {
		return EffectClosureRecord{}, err
	}

	acknowledgement := request.Acknowledgement.Acknowledgement
	if err := effectAcknowledgementMatchesReservation(acknowledgement, current, identity); err != nil {
		return EffectClosureRecord{}, err
	}
	if err := s.effectAcknowledgementMatchesDisposition(
		ctx, tx, identity, acknowledgement, releaseAuthorities, dispositionVerifier, true,
	); err != nil {
		return EffectClosureRecord{}, err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return EffectClosureRecord{}, fmt.Errorf("read effect close database clock: %w", err)
	}
	now = now.UTC().Truncate(time.Microsecond)
	earliestObservation := current.AdmittedAt
	if current.StartedAt != nil {
		earliestObservation = *current.StartedAt
	} else if current.State == EffectReservationStateUncertain {
		earliestObservation = current.OccurredAt
	}
	if acknowledgement.ObservedAt.Add(contracts.EffectCloseMaxClockSkew).Before(earliestObservation) ||
		acknowledgement.ObservedAt.After(now.Add(contracts.EffectCloseMaxClockSkew)) {
		return EffectClosureRecord{}, fmt.Errorf("%w: acknowledgement observed_at is outside the reservation timeline", ErrEffectCloseConflict)
	}

	headHash, err := effectReservationHeadHash(current)
	if err != nil {
		return EffectClosureRecord{}, err
	}
	closeID, err := deterministicEffectCloseID(request)
	if err != nil {
		return EffectClosureRecord{}, err
	}
	admission := current.Admission.Admission
	receipt, err := (contracts.EffectCloseReceipt{
		SchemaVersion: contracts.EffectCloseReceiptSchemaV1, ContractVersion: contracts.EffectCloseReceiptContractV1,
		CloseID: closeID, State: contracts.EffectCloseReceiptStateClosed,
		AdmissionID: admission.AdmissionID, AttemptID: admission.AttemptID,
		TenantID: identity.TenantID, WorkspaceID: identity.WorkspaceID, Audience: identity.Audience,
		ConnectorID: acknowledgement.ConnectorID, ConnectorVersion: acknowledgement.ConnectorVersion,
		ConnectorAction: acknowledgement.ConnectorAction,
		PriorState:      string(current.State), ReservationSequence: current.Sequence, ReservationHeadHash: headHash,
		AcknowledgementHash: acknowledgement.AcknowledgementHash, Outcome: acknowledgement.Outcome,
		IdempotencyKeyHash: admission.IdempotencyKeyHash, EffectHash: admission.EffectHash,
		ResponseHash:          acknowledgement.ResponseHash,
		ConnectorExecutionRef: acknowledgement.ConnectorExecutionRef,
		ProofSessionRef:       acknowledgement.ProofSessionRef, IntentRef: acknowledgement.IntentRef,
		EffectRef: acknowledgement.EffectRef, ReconciliationRef: acknowledgement.ReconciliationRef,
		DispositionReceiptHash: acknowledgement.DispositionReceiptHash,
		EvidencePackRef:        request.EvidencePackRef, EvidencePackHash: request.EvidencePackHash,
		KernelTrustRootID: admission.KernelTrustRootID, SigningKeyRef: admission.SigningKeyRef,
		ClosedBy: identity.Subject, ClosedAt: now,
	}).Seal()
	if err != nil {
		return EffectClosureRecord{}, err
	}
	if err := receipt.ValidateAcknowledgement(acknowledgement); err != nil {
		return EffectClosureRecord{}, err
	}
	signature, err := SignEffectCloseReceipt(receipt, signer)
	if err != nil {
		return EffectClosureRecord{}, err
	}
	record := EffectClosureRecord{
		Acknowledgement: request.Acknowledgement, Receipt: receipt,
		SignatureAlgorithm: GrantSignatureEd25519, Signature: signature, CreatedAt: now,
	}
	if err := verifyEffectClosureSignatures(s, record, acknowledgementVerifier); err != nil {
		return EffectClosureRecord{}, err
	}
	created, err := insertEffectClosureRecord(ctx, tx, record)
	if err != nil {
		return EffectClosureRecord{}, err
	}

	completed := current
	completed.Sequence++
	completed.State = EffectReservationStateCompleted
	completed.ResolvedAt = timePointer(now)
	completed.OccurredAt = now
	completed.ReasonCode = ""
	completed.ConnectorExecutionRef = acknowledgement.ConnectorExecutionRef
	completed.ProofSessionRef = acknowledgement.ProofSessionRef
	completed.IntentRef = acknowledgement.IntentRef
	completed.EffectRef = acknowledgement.EffectRef
	completed.ClosePriorState = string(current.State)
	completed.AcknowledgementHash = acknowledgement.AcknowledgementHash
	completed.CloseReceiptHash = receipt.ReceiptHash
	completed.Outcome = acknowledgement.Outcome
	completed.EvidencePackRef = request.EvidencePackRef
	completed.EvidencePackHash = request.EvidencePackHash
	completed.ReconciliationRef = acknowledgement.ReconciliationRef
	if _, err := insertEffectReservationEvent(ctx, tx, completed); err != nil {
		return EffectClosureRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return EffectClosureRecord{}, fmt.Errorf("commit effect close: %w", err)
	}
	return created, nil
}

func (s *PostgresStore) recoverEffectClosure(
	ctx context.Context,
	identity ConsumerIdentity,
	admissionID string,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
	acknowledgementVerifier EffectAcknowledgementVerifier,
	dispositionVerifier EffectDispositionCommandVerifier,
) (EffectClosureRecord, error) {
	if s == nil || s.db == nil || s.grantVerifier == nil || releaseAuthorities == nil ||
		acknowledgementVerifier == nil || dispositionVerifier == nil {
		return EffectClosureRecord{}, errors.New("effect close store is not configured")
	}
	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return EffectClosureRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := queryCurrentEffectReservation(ctx, tx, identity.TenantID, identity.WorkspaceID, admissionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EffectClosureRecord{}, ErrNotFound
		}
		return EffectClosureRecord{}, err
	}
	if err := exactEffectReservationIdentity(current, identity); err != nil {
		return EffectClosureRecord{}, err
	}
	if current.State != EffectReservationStateCompleted {
		return EffectClosureRecord{}, ErrEffectCloseTerminal
	}
	record, err := queryEffectClosureRecord(ctx, tx, identity.TenantID, identity.WorkspaceID, admissionID)
	if err != nil {
		return EffectClosureRecord{}, err
	}
	if err := s.verifyEffectClosureRecord(
		ctx, tx, current, record, releaseAuthorities, acknowledgementVerifier, dispositionVerifier,
	); err != nil {
		return EffectClosureRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return EffectClosureRecord{}, fmt.Errorf("commit effect close recovery: %w", err)
	}
	return record, nil
}

func effectAcknowledgementMatchesReservation(
	acknowledgement contracts.ConnectorEffectAcknowledgement,
	current EffectReservationEvent,
	identity ConsumerIdentity,
) error {
	admission := current.Admission.Admission
	authority := admission.ConnectorAuthority
	release := current.ReleaseAuthority.Authority
	if acknowledgement.AdmissionID != admission.AdmissionID || acknowledgement.AttemptID != admission.AttemptID ||
		acknowledgement.TenantID != identity.TenantID || acknowledgement.WorkspaceID != identity.WorkspaceID ||
		acknowledgement.Audience != identity.Audience || acknowledgement.ConnectorID != authority.ConnectorID ||
		acknowledgement.ConnectorVersion != authority.ConnectorVersion ||
		acknowledgement.ConnectorAction != authority.ConnectorAction ||
		acknowledgement.IdempotencyKeyHash != admission.IdempotencyKeyHash ||
		acknowledgement.EffectHash != admission.EffectHash || acknowledgement.IssuerID != release.ConnectorSignerID ||
		acknowledgement.ConnectorExecutionRef != current.ConnectorExecutionRef ||
		acknowledgement.ProofSessionRef != current.ProofSessionRef || acknowledgement.IntentRef != current.IntentRef {
		return ErrEffectCloseConflict
	}
	if current.EffectRef != "" && acknowledgement.EffectRef != current.EffectRef {
		return ErrEffectCloseConflict
	}
	if current.State == EffectReservationStateUncertain && acknowledgement.ReconciliationRef == "" {
		return ErrEffectCloseConflict
	}
	return nil
}

func (s *PostgresStore) verifyEffectClosureRecord(
	ctx context.Context,
	tx *sql.Tx,
	completed EffectReservationEvent,
	record EffectClosureRecord,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
	acknowledgementVerifier EffectAcknowledgementVerifier,
	dispositionVerifier EffectDispositionCommandVerifier,
) error {
	if completed.State != EffectReservationStateCompleted || completed.Sequence < 3 {
		return ErrEffectCloseConflict
	}
	if err := verifyEffectClosureSignatures(s, record, acknowledgementVerifier); err != nil {
		return err
	}
	prior, err := queryEffectReservationAtSequence(
		ctx, tx, completed.Admission.Admission.TenantID, completed.Admission.Admission.WorkspaceID,
		completed.Admission.Admission.AdmissionID, completed.Sequence-1,
	)
	if err != nil {
		return err
	}
	priorIdentity := ConsumerIdentity{
		Subject:  prior.Admission.Admission.AdmittedBy,
		TenantID: prior.Admission.Admission.TenantID, WorkspaceID: prior.Admission.Admission.WorkspaceID,
		Audience: prior.Admission.Admission.Audience,
	}
	if err := effectAcknowledgementMatchesReservation(record.Acknowledgement.Acknowledgement, prior, priorIdentity); err != nil {
		return err
	}
	if err := s.effectAcknowledgementMatchesDisposition(
		ctx, tx, priorIdentity, record.Acknowledgement.Acknowledgement, releaseAuthorities, dispositionVerifier, false,
	); err != nil {
		return err
	}
	headHash, err := effectReservationHeadHash(prior)
	if err != nil {
		return err
	}
	receipt := record.Receipt
	if receipt.ReservationHeadHash != headHash || receipt.ReservationSequence != prior.Sequence ||
		receipt.PriorState != string(prior.State) || completed.ClosePriorState != string(prior.State) ||
		receipt.AdmissionID != completed.Admission.Admission.AdmissionID ||
		receipt.ReceiptHash != completed.CloseReceiptHash || receipt.AcknowledgementHash != completed.AcknowledgementHash ||
		receipt.Outcome != completed.Outcome || receipt.EvidencePackRef != completed.EvidencePackRef ||
		receipt.EvidencePackHash != completed.EvidencePackHash || receipt.ReconciliationRef != completed.ReconciliationRef ||
		receipt.ConnectorExecutionRef != completed.ConnectorExecutionRef || receipt.ProofSessionRef != completed.ProofSessionRef ||
		receipt.IntentRef != completed.IntentRef || receipt.EffectRef != completed.EffectRef ||
		!receipt.ClosedAt.Equal(completed.OccurredAt) {
		return ErrEffectCloseConflict
	}
	return nil
}

func (s *PostgresStore) effectAcknowledgementMatchesDisposition(
	ctx context.Context,
	tx *sql.Tx,
	identity ConsumerIdentity,
	acknowledgement contracts.ConnectorEffectAcknowledgement,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
	dispositionVerifier EffectDispositionCommandVerifier,
	requireCurrentFence bool,
) error {
	if s == nil || releaseAuthorities == nil || dispositionVerifier == nil {
		return errors.New("effect disposition verification is not configured for close")
	}
	var currentFence kernel.FenceState
	fenceErr := sql.ErrNoRows
	if requireCurrentFence {
		currentFence, fenceErr = queryEffectDispositionFence(
			ctx, tx, acknowledgement.TenantID, acknowledgement.WorkspaceID,
		)
		if fenceErr != nil && !errors.Is(fenceErr, sql.ErrNoRows) {
			return fenceErr
		}
	}
	record, err := queryLatestEffectDispositionForEffect(
		ctx, tx, acknowledgement.TenantID, acknowledgement.WorkspaceID, acknowledgement.AdmissionID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if fenceErr == nil || acknowledgement.DispositionReceiptHash != "" {
			return ErrEffectCloseConflict
		}
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.verifyEffectDispositionRecord(ctx, tx, identity, record, releaseAuthorities, dispositionVerifier); err != nil {
		return err
	}
	if record.Command.Command.Action == contracts.EffectDispositionActionHold ||
		(requireCurrentFence && (errors.Is(fenceErr, sql.ErrNoRows) ||
			effectDispositionCommandMatchesFence(record.Command.Command, currentFence) != nil)) {
		return ErrEffectCloseConflict
	}
	if acknowledgement.DispositionReceiptHash != record.Receipt.ReceiptHash ||
		acknowledgement.ReconciliationRef != record.Command.Command.DispositionRef {
		return ErrEffectCloseConflict
	}
	return nil
}

func verifyEffectClosureSignatures(
	store *PostgresStore,
	record EffectClosureRecord,
	acknowledgementVerifier EffectAcknowledgementVerifier,
) error {
	if store == nil || store.grantVerifier == nil || acknowledgementVerifier == nil {
		return errors.New("effect close verifiers are not configured")
	}
	if err := record.Validate(); err != nil {
		return err
	}
	// A persisted closure record is historical evidence (recovery + idempotency
	// re-checks), so tolerate a signing key disabled/rotated after the
	// acknowledgement was observed; signature + pinned lifetime still enforced.
	if err := acknowledgementVerifier.VerifyStoredEnvelope(record.Acknowledgement); err != nil {
		return err
	}
	return store.grantVerifier.VerifyEffectCloseReceiptSignature(
		record.Receipt, record.SignatureAlgorithm, record.Signature,
	)
}

func effectReservationHeadHash(event EffectReservationEvent) (string, error) {
	hash, err := canonicalize.CanonicalHash(event)
	if err != nil {
		return "", fmt.Errorf("hash effect reservation head: %w", err)
	}
	return "sha256:" + hash, nil
}

func deterministicEffectCloseID(request EffectCloseRequest) (string, error) {
	hash, err := canonicalize.CanonicalHash(struct {
		AdmissionID         string `json:"admission_id"`
		AcknowledgementHash string `json:"acknowledgement_hash"`
		EvidencePackHash    string `json:"evidence_pack_hash"`
	}{
		AdmissionID:         request.AdmissionID,
		AcknowledgementHash: request.Acknowledgement.Acknowledgement.AcknowledgementHash,
		EvidencePackHash:    request.EvidencePackHash,
	})
	if err != nil {
		return "", fmt.Errorf("derive effect close id: %w", err)
	}
	return "effect-close-" + hash[:32], nil
}

func effectCloseRequestMatchesRecord(request EffectCloseRequest, record EffectClosureRecord) bool {
	return request.Acknowledgement == record.Acknowledgement &&
		request.EvidencePackRef == record.Receipt.EvidencePackRef &&
		request.EvidencePackHash == record.Receipt.EvidencePackHash
}

func insertEffectClosureRecord(ctx context.Context, tx *sql.Tx, record EffectClosureRecord) (EffectClosureRecord, error) {
	if err := record.Validate(); err != nil {
		return EffectClosureRecord{}, err
	}
	acknowledgementJSON, err := json.Marshal(record.Acknowledgement)
	if err != nil {
		return EffectClosureRecord{}, fmt.Errorf("marshal effect acknowledgement: %w", err)
	}
	receiptJSON, err := json.Marshal(record.Receipt)
	if err != nil {
		return EffectClosureRecord{}, fmt.Errorf("marshal effect close receipt: %w", err)
	}
	r := record.Receipt
	return scanEffectClosureRecord(tx.QueryRowContext(ctx, `INSERT INTO approval_effect_closures (
		tenant_id, workspace_id, admission_id, close_id,
		acknowledgement_hash, receipt_hash, outcome,
		evidence_pack_ref, evidence_pack_hash,
		acknowledgement_json, receipt_json,
		signature_algorithm, signature, created_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
	RETURNING `+effectClosureColumns,
		r.TenantID, r.WorkspaceID, r.AdmissionID, r.CloseID,
		r.AcknowledgementHash, r.ReceiptHash, r.Outcome,
		r.EvidencePackRef, r.EvidencePackHash,
		acknowledgementJSON, receiptJSON,
		record.SignatureAlgorithm, record.Signature, record.CreatedAt,
	))
}

func queryEffectClosureRecord(
	ctx context.Context,
	tx *sql.Tx,
	tenantID, workspaceID, admissionID string,
) (EffectClosureRecord, error) {
	return scanEffectClosureRecord(tx.QueryRowContext(ctx, `SELECT `+effectClosureColumns+`
		FROM approval_effect_closures
		WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3`, tenantID, workspaceID, admissionID))
}

type effectClosureScanner interface {
	Scan(...any) error
}

func scanEffectClosureRecord(scanner effectClosureScanner) (EffectClosureRecord, error) {
	var record EffectClosureRecord
	var tenantID, workspaceID, admissionID, closeID string
	var acknowledgementHash, receiptHash, outcome, evidencePackRef, evidencePackHash string
	var acknowledgementJSON, receiptJSON []byte
	if err := scanner.Scan(
		&tenantID, &workspaceID, &admissionID, &closeID,
		&acknowledgementHash, &receiptHash, &outcome,
		&evidencePackRef, &evidencePackHash,
		&acknowledgementJSON, &receiptJSON,
		&record.SignatureAlgorithm, &record.Signature, &record.CreatedAt,
	); err != nil {
		return EffectClosureRecord{}, err
	}
	if err := json.Unmarshal(acknowledgementJSON, &record.Acknowledgement); err != nil {
		return EffectClosureRecord{}, fmt.Errorf("decode effect acknowledgement: %w", err)
	}
	if err := json.Unmarshal(receiptJSON, &record.Receipt); err != nil {
		return EffectClosureRecord{}, fmt.Errorf("decode effect close receipt: %w", err)
	}
	if record.Receipt.TenantID != tenantID || record.Receipt.WorkspaceID != workspaceID ||
		record.Receipt.AdmissionID != admissionID || record.Receipt.CloseID != closeID ||
		record.Receipt.AcknowledgementHash != acknowledgementHash || record.Receipt.ReceiptHash != receiptHash ||
		record.Receipt.Outcome != outcome || record.Receipt.EvidencePackRef != evidencePackRef ||
		record.Receipt.EvidencePackHash != evidencePackHash {
		return EffectClosureRecord{}, ErrEffectCloseConflict
	}
	record.CreatedAt = record.CreatedAt.UTC()
	if err := record.Validate(); err != nil {
		return EffectClosureRecord{}, err
	}
	return record, nil
}

func queryEffectReservationAtSequence(
	ctx context.Context,
	tx *sql.Tx,
	tenantID, workspaceID, admissionID string,
	sequence uint64,
) (EffectReservationEvent, error) {
	return scanEffectReservationEvent(tx.QueryRowContext(ctx, `SELECT `+effectReservationColumns+`
		FROM approval_effect_reservation_events
		WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3 AND sequence = $4`,
		tenantID, workspaceID, admissionID, sequence,
	))
}
