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

const effectDispositionColumns = `
tenant_id, workspace_id, admission_id, command_id, disposition_sequence,
command_hash, previous_receipt_hash, action, disposition_ref,
fence_command_id, fence_command_hash, fence_epoch, fence_receipt_hash,
reservation_sequence, reservation_head_hash, reservation_state,
fence_json, command_envelope_json, receipt_json,
signature_algorithm, signature, created_at
`

func (s *PostgresStore) recordEffectDisposition(
	ctx context.Context,
	identity ConsumerIdentity,
	envelope contracts.EffectDispositionCommandEnvelope,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
	commandVerifier EffectDispositionCommandVerifier,
	signer crypto.Signer,
) (EffectDispositionRecord, error) {
	if s == nil || s.db == nil || s.grantVerifier == nil || releaseAuthorities == nil ||
		commandVerifier == nil || signer == nil {
		return EffectDispositionRecord{}, errors.New("effect disposition store is not configured")
	}
	if err := commandVerifier.VerifyEnvelope(envelope); err != nil {
		return EffectDispositionRecord{}, err
	}
	command := envelope.Command
	if command.TenantID != identity.TenantID || command.WorkspaceID != identity.WorkspaceID ||
		command.Audience != identity.Audience {
		return EffectDispositionRecord{}, ErrEffectDispositionConflict
	}

	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return EffectDispositionRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockApprovalScope(ctx, tx, identity.TenantID, identity.WorkspaceID); err != nil {
		return EffectDispositionRecord{}, err
	}

	existing, err := queryEffectDispositionByCommandID(ctx, tx, identity.TenantID, identity.WorkspaceID, command.CommandID)
	if err == nil {
		if err := s.verifyEffectDispositionRecord(ctx, tx, identity, existing, releaseAuthorities, commandVerifier); err != nil {
			return EffectDispositionRecord{}, err
		}
		if existing.Command != envelope {
			return EffectDispositionRecord{}, ErrEffectDispositionConflict
		}
		if err := tx.Commit(); err != nil {
			return EffectDispositionRecord{}, fmt.Errorf("commit effect disposition replay: %w", err)
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return EffectDispositionRecord{}, err
	}

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return EffectDispositionRecord{}, fmt.Errorf("read effect disposition database clock: %w", err)
	}
	now = now.UTC().Truncate(time.Microsecond)
	if command.IssuedAt.After(now.Add(contracts.EffectDispositionMaxCommandFutureClockSkew)) || !now.Before(command.ExpiresAt) {
		return EffectDispositionRecord{}, effectDispositionCommandRejected("command is not currently live")
	}

	fence, err := queryEffectDispositionFence(ctx, tx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EffectDispositionRecord{}, ErrEffectDispositionRequiresFence
		}
		return EffectDispositionRecord{}, err
	}
	if err := effectDispositionCommandMatchesFence(command, fence); err != nil {
		return EffectDispositionRecord{}, err
	}

	reservation, err := queryCurrentEffectReservation(ctx, tx, identity.TenantID, identity.WorkspaceID, command.AdmissionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EffectDispositionRecord{}, ErrNotFound
		}
		return EffectDispositionRecord{}, err
	}
	if err := exactEffectReservationIdentity(reservation, identity); err != nil {
		return EffectDispositionRecord{}, err
	}
	if err := s.verifyEffectReservationAuthorities(reservation, releaseAuthorities); err != nil {
		return EffectDispositionRecord{}, err
	}
	if reservation.State != EffectReservationStateStarted && reservation.State != EffectReservationStateUncertain {
		return EffectDispositionRecord{}, ErrEffectDispositionTerminal
	}
	if err := effectDispositionCommandMatchesReservation(command, reservation); err != nil {
		return EffectDispositionRecord{}, err
	}

	chain, err := queryEffectDispositionRecordsForEffect(
		ctx, tx, identity.TenantID, identity.WorkspaceID, command.AdmissionID,
	)
	if err != nil {
		return EffectDispositionRecord{}, err
	}
	for _, prior := range chain {
		if err := s.verifyEffectDispositionRecord(ctx, tx, identity, prior, releaseAuthorities, commandVerifier); err != nil {
			return EffectDispositionRecord{}, err
		}
	}
	var lastReceiptHash string
	var lastSequence uint64
	if len(chain) > 0 {
		last := chain[len(chain)-1]
		lastReceiptHash = last.Receipt.ReceiptHash
		lastSequence = last.Receipt.DispositionSequence
	}
	if command.DispositionSequence != lastSequence+1 || command.PreviousReceiptHash != lastReceiptHash {
		return EffectDispositionRecord{}, ErrEffectDispositionConflict
	}

	receiptID, err := deterministicEffectDispositionReceiptID(command)
	if err != nil {
		return EffectDispositionRecord{}, err
	}
	admission := reservation.Admission.Admission
	receipt, err := (contracts.EffectDispositionReceipt{
		SchemaVersion: contracts.EffectDispositionReceiptSchemaV1, ContractVersion: contracts.EffectDispositionReceiptContractV1,
		ReceiptID: receiptID, State: contracts.EffectDispositionReceiptStateAccepted,
		ExecutionAuthority: contracts.EffectDispositionExecutionAuthorityNone,
		CommandID:          command.CommandID, CommandHash: command.CommandHash,
		DispositionSequence: command.DispositionSequence, PreviousReceiptHash: command.PreviousReceiptHash,
		TenantID: identity.TenantID, WorkspaceID: identity.WorkspaceID, Audience: identity.Audience,
		FenceCommandID: command.FenceCommandID, FenceCommandHash: command.FenceCommandHash,
		FenceEpoch: command.FenceEpoch, FenceReceiptHash: command.FenceReceiptHash,
		AdmissionID: command.AdmissionID, ReservationSequence: command.ReservationSequence,
		ReservationHeadHash: command.ReservationHeadHash, ReservationState: command.ReservationState,
		Action: command.Action, DispositionRef: command.DispositionRef,
		KernelTrustRootID: admission.KernelTrustRootID, SigningKeyRef: admission.SigningKeyRef,
		AcceptedBy: identity.Subject, AcceptedAt: now,
	}).Seal()
	if err != nil {
		return EffectDispositionRecord{}, err
	}
	signature, err := SignEffectDispositionReceipt(receipt, signer)
	if err != nil {
		return EffectDispositionRecord{}, err
	}
	record := EffectDispositionRecord{
		Command: envelope, Fence: fence, Receipt: receipt,
		SignatureAlgorithm: GrantSignatureEd25519, Signature: signature, CreatedAt: now,
	}
	if err := verifyEffectDispositionSignatures(s, record, commandVerifier); err != nil {
		return EffectDispositionRecord{}, err
	}
	created, err := insertEffectDispositionRecord(ctx, tx, record)
	if err != nil {
		return EffectDispositionRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return EffectDispositionRecord{}, fmt.Errorf("commit effect disposition: %w", err)
	}
	return created, nil
}

func (s *PostgresStore) recoverEffectDisposition(
	ctx context.Context,
	identity ConsumerIdentity,
	commandID string,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
	commandVerifier EffectDispositionCommandVerifier,
) (EffectDispositionRecord, error) {
	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return EffectDispositionRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := queryEffectDispositionByCommandID(ctx, tx, identity.TenantID, identity.WorkspaceID, commandID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EffectDispositionRecord{}, ErrNotFound
		}
		return EffectDispositionRecord{}, err
	}
	if err := s.verifyEffectDispositionRecord(ctx, tx, identity, record, releaseAuthorities, commandVerifier); err != nil {
		return EffectDispositionRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return EffectDispositionRecord{}, fmt.Errorf("commit effect disposition recovery: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) listEffectDispositions(
	ctx context.Context,
	identity ConsumerIdentity,
	admissionID string,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
	commandVerifier EffectDispositionCommandVerifier,
) ([]EffectDispositionRecord, error) {
	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	records, err := queryEffectDispositionRecordsForEffect(
		ctx, tx, identity.TenantID, identity.WorkspaceID, admissionID,
	)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if err := s.verifyEffectDispositionRecord(ctx, tx, identity, record, releaseAuthorities, commandVerifier); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit effect disposition listing: %w", err)
	}
	return records, nil
}

func (s *PostgresStore) verifyEffectDispositionRecord(
	ctx context.Context,
	tx *sql.Tx,
	identity ConsumerIdentity,
	record EffectDispositionRecord,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
	commandVerifier EffectDispositionCommandVerifier,
) error {
	if err := verifyEffectDispositionSignatures(s, record, commandVerifier); err != nil {
		return err
	}
	command := record.Command.Command
	if command.TenantID != identity.TenantID || command.WorkspaceID != identity.WorkspaceID || command.Audience != identity.Audience {
		return ErrEffectDispositionConflict
	}
	reservation, err := queryEffectReservationAtSequence(
		ctx, tx, identity.TenantID, identity.WorkspaceID, command.AdmissionID, command.ReservationSequence,
	)
	if err != nil {
		return err
	}
	if err := exactEffectReservationIdentity(reservation, identity); err != nil {
		return err
	}
	if err := s.verifyEffectReservationAuthorities(reservation, releaseAuthorities); err != nil {
		return err
	}
	if err := effectDispositionCommandMatchesReservation(command, reservation); err != nil {
		return err
	}
	if command.DispositionSequence > 1 {
		var previousReceiptHash string
		if err := tx.QueryRowContext(ctx, `SELECT receipt_json->>'receipt_hash'
			FROM approval_effect_dispositions
			WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3 AND disposition_sequence = $4`,
			identity.TenantID, identity.WorkspaceID, command.AdmissionID, command.DispositionSequence-1,
		).Scan(&previousReceiptHash); err != nil {
			return err
		}
		if previousReceiptHash != command.PreviousReceiptHash {
			return ErrEffectDispositionConflict
		}
	}
	return nil
}

func verifyEffectDispositionSignatures(
	store *PostgresStore,
	record EffectDispositionRecord,
	commandVerifier EffectDispositionCommandVerifier,
) error {
	if store == nil || store.grantVerifier == nil || commandVerifier == nil {
		return errors.New("effect disposition verifiers are not configured")
	}
	if err := record.Validate(); err != nil {
		return err
	}
	if err := commandVerifier.VerifyEnvelope(record.Command); err != nil {
		return err
	}
	return store.grantVerifier.VerifyEffectDispositionReceiptSignature(
		record.Receipt, record.SignatureAlgorithm, record.Signature,
	)
}

func effectDispositionCommandMatchesFence(command contracts.EffectDispositionCommand, fence kernel.FenceState) error {
	if fence.TenantID != command.TenantID || fence.WorkspaceID != command.WorkspaceID ||
		fence.CommandID != command.FenceCommandID || fence.CommandHash != command.FenceCommandHash ||
		fence.Epoch != command.FenceEpoch || fence.ReceiptHash != command.FenceReceiptHash {
		return ErrEffectDispositionConflict
	}
	return nil
}

func effectDispositionCommandMatchesReservation(
	command contracts.EffectDispositionCommand,
	reservation EffectReservationEvent,
) error {
	admission := reservation.Admission.Admission
	headHash, err := effectReservationHeadHash(reservation)
	if err != nil {
		return err
	}
	if command.AdmissionID != admission.AdmissionID || command.AttemptID != admission.AttemptID ||
		command.ReservationSequence != reservation.Sequence || command.ReservationHeadHash != headHash ||
		command.ReservationState != string(reservation.State) ||
		command.ConnectorID != admission.ConnectorAuthority.ConnectorID ||
		command.ConnectorVersion != admission.ConnectorAuthority.ConnectorVersion ||
		command.ConnectorAction != admission.ConnectorAuthority.ConnectorAction ||
		command.ConnectorExecutionRef != reservation.ConnectorExecutionRef ||
		command.ProofSessionRef != reservation.ProofSessionRef || command.IntentRef != reservation.IntentRef ||
		command.EffectRef != reservation.EffectRef || command.IdempotencyKeyHash != admission.IdempotencyKeyHash ||
		command.EffectHash != admission.EffectHash {
		return ErrEffectDispositionConflict
	}
	return nil
}

func deterministicEffectDispositionReceiptID(command contracts.EffectDispositionCommand) (string, error) {
	hash, err := canonicalize.CanonicalHash(struct {
		CommandID   string `json:"command_id"`
		CommandHash string `json:"command_hash"`
	}{CommandID: command.CommandID, CommandHash: command.CommandHash})
	if err != nil {
		return "", fmt.Errorf("derive effect disposition receipt id: %w", err)
	}
	return "effect-disposition-receipt-" + hash[:32], nil
}

func queryEffectDispositionFence(
	ctx context.Context,
	tx *sql.Tx,
	tenantID, workspaceID string,
) (kernel.FenceState, error) {
	var state kernel.FenceState
	var issuedAt, expiresAt, fencedAt string
	err := tx.QueryRowContext(ctx, `SELECT contract_version, audience, key_id, command_id, command_hash, epoch,
		actor_id, reason, issued_at, expires_at, fenced_at,
		kernel_key_id, kernel_signer_profile, kernel_public_key, receipt_hash
		FROM emergency_stop_fences WHERE tenant_id = $1 AND workspace_id = $2`, tenantID, workspaceID).Scan(
		&state.ContractVersion, &state.Audience, &state.KeyID, &state.CommandID, &state.CommandHash, &state.Epoch,
		&state.ActorID, &state.Reason, &issuedAt, &expiresAt, &fencedAt,
		&state.AcknowledgementIdentity.KeyID, &state.AcknowledgementIdentity.SignerProfile,
		&state.AcknowledgementIdentity.PublicKey, &state.ReceiptHash,
	)
	if err != nil {
		return kernel.FenceState{}, err
	}
	state.StopScope = kernel.StopScope{TenantID: tenantID, WorkspaceID: workspaceID}
	state.IssuedAt, err = parseEffectDispositionFenceTime(issuedAt)
	if err != nil {
		return kernel.FenceState{}, err
	}
	state.ExpiresAt, err = parseEffectDispositionFenceTime(expiresAt)
	if err != nil {
		return kernel.FenceState{}, err
	}
	state.FencedAt, err = parseEffectDispositionFenceTime(fencedAt)
	if err != nil {
		return kernel.FenceState{}, err
	}
	return state, nil
}

func parseEffectDispositionFenceTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse effect disposition fence timestamp: %w", err)
	}
	return parsed, nil
}

func insertEffectDispositionRecord(ctx context.Context, tx *sql.Tx, record EffectDispositionRecord) (EffectDispositionRecord, error) {
	if err := record.Validate(); err != nil {
		return EffectDispositionRecord{}, err
	}
	fenceJSON, err := json.Marshal(record.Fence)
	if err != nil {
		return EffectDispositionRecord{}, fmt.Errorf("marshal effect disposition fence: %w", err)
	}
	commandJSON, err := json.Marshal(record.Command)
	if err != nil {
		return EffectDispositionRecord{}, fmt.Errorf("marshal effect disposition command: %w", err)
	}
	receiptJSON, err := json.Marshal(record.Receipt)
	if err != nil {
		return EffectDispositionRecord{}, fmt.Errorf("marshal effect disposition receipt: %w", err)
	}
	c := record.Command.Command
	return scanEffectDispositionRecord(tx.QueryRowContext(ctx, `INSERT INTO approval_effect_dispositions (
		tenant_id, workspace_id, admission_id, command_id, disposition_sequence,
		command_hash, previous_receipt_hash, action, disposition_ref,
		fence_command_id, fence_command_hash, fence_epoch, fence_receipt_hash,
		reservation_sequence, reservation_head_hash, reservation_state,
		fence_json, command_envelope_json, receipt_json,
		signature_algorithm, signature, created_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
	RETURNING `+effectDispositionColumns,
		c.TenantID, c.WorkspaceID, c.AdmissionID, c.CommandID, c.DispositionSequence,
		c.CommandHash, nullableToken(c.PreviousReceiptHash), c.Action, c.DispositionRef,
		c.FenceCommandID, c.FenceCommandHash, c.FenceEpoch, c.FenceReceiptHash,
		c.ReservationSequence, c.ReservationHeadHash, c.ReservationState,
		fenceJSON, commandJSON, receiptJSON, record.SignatureAlgorithm, record.Signature, record.CreatedAt,
	))
}

func queryEffectDispositionByCommandID(
	ctx context.Context,
	tx *sql.Tx,
	tenantID, workspaceID, commandID string,
) (EffectDispositionRecord, error) {
	return scanEffectDispositionRecord(tx.QueryRowContext(ctx, `SELECT `+effectDispositionColumns+`
		FROM approval_effect_dispositions
		WHERE tenant_id = $1 AND workspace_id = $2 AND command_id = $3`, tenantID, workspaceID, commandID))
}

func queryLatestEffectDispositionForEffect(
	ctx context.Context,
	tx *sql.Tx,
	tenantID, workspaceID, admissionID string,
) (EffectDispositionRecord, error) {
	return scanEffectDispositionRecord(tx.QueryRowContext(ctx, `SELECT `+effectDispositionColumns+`
		FROM approval_effect_dispositions
		WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3
		ORDER BY disposition_sequence DESC LIMIT 1`, tenantID, workspaceID, admissionID))
}

func queryEffectDispositionRecordsForEffect(
	ctx context.Context,
	tx *sql.Tx,
	tenantID, workspaceID, admissionID string,
) ([]EffectDispositionRecord, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+effectDispositionColumns+`
		FROM approval_effect_dispositions
		WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3
		ORDER BY disposition_sequence`, tenantID, workspaceID, admissionID)
	if err != nil {
		return nil, fmt.Errorf("list effect dispositions: %w", err)
	}
	defer rows.Close()
	records := make([]EffectDispositionRecord, 0)
	for rows.Next() {
		record, err := scanEffectDispositionRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate effect dispositions: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close effect disposition rows: %w", err)
	}
	return records, nil
}

func scanEffectDispositionRecord(scanner rowScanner) (EffectDispositionRecord, error) {
	var record EffectDispositionRecord
	var tenantID, workspaceID, admissionID, commandID string
	var commandHash, action, dispositionRef string
	var fenceCommandID, fenceCommandHash, fenceReceiptHash string
	var reservationHeadHash, reservationState string
	var previousReceiptHash sql.NullString
	var dispositionSequence, fenceEpoch, reservationSequence uint64
	var fenceJSON, commandJSON, receiptJSON []byte
	if err := scanner.Scan(
		&tenantID, &workspaceID, &admissionID, &commandID, &dispositionSequence,
		&commandHash, &previousReceiptHash, &action, &dispositionRef,
		&fenceCommandID, &fenceCommandHash, &fenceEpoch, &fenceReceiptHash,
		&reservationSequence, &reservationHeadHash, &reservationState,
		&fenceJSON, &commandJSON, &receiptJSON,
		&record.SignatureAlgorithm, &record.Signature, &record.CreatedAt,
	); err != nil {
		return EffectDispositionRecord{}, err
	}
	if err := json.Unmarshal(fenceJSON, &record.Fence); err != nil {
		return EffectDispositionRecord{}, fmt.Errorf("decode effect disposition fence: %w", err)
	}
	if err := json.Unmarshal(commandJSON, &record.Command); err != nil {
		return EffectDispositionRecord{}, fmt.Errorf("decode effect disposition command: %w", err)
	}
	if err := json.Unmarshal(receiptJSON, &record.Receipt); err != nil {
		return EffectDispositionRecord{}, fmt.Errorf("decode effect disposition receipt: %w", err)
	}
	c := record.Command.Command
	if c.TenantID != tenantID || c.WorkspaceID != workspaceID || c.AdmissionID != admissionID || c.CommandID != commandID ||
		c.DispositionSequence != dispositionSequence || c.CommandHash != commandHash || c.PreviousReceiptHash != previousReceiptHash.String ||
		c.Action != action || c.DispositionRef != dispositionRef || c.FenceCommandID != fenceCommandID ||
		c.FenceCommandHash != fenceCommandHash || c.FenceEpoch != fenceEpoch || c.FenceReceiptHash != fenceReceiptHash ||
		c.ReservationSequence != reservationSequence || c.ReservationHeadHash != reservationHeadHash ||
		c.ReservationState != reservationState {
		return EffectDispositionRecord{}, ErrEffectDispositionConflict
	}
	record.CreatedAt = record.CreatedAt.UTC()
	if err := record.Validate(); err != nil {
		return EffectDispositionRecord{}, err
	}
	return record, nil
}
