package approvalceremony

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	connectorregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry/connectors"
)

// ListReconciliationCandidates returns only source-owned bindings needed to
// construct a later RECONCILE_SOURCE command. It never grants connector effect
// authority, and command acceptance always rereads the FENCE and head.
func (s *EffectDispositionService) ListReconciliationCandidates(
	ctx context.Context,
) (contracts.EffectReconciliationCandidates, error) {
	if s == nil || s.store == nil || s.commandVerifier == nil {
		return contracts.EffectReconciliationCandidates{}, errors.New("effect disposition service is not initialized")
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return contracts.EffectReconciliationCandidates{}, err
	}
	return s.store.listEffectReconciliationCandidates(
		ctx, identity, s.releaseAuthorities, s.commandVerifier,
	)
}

func (s *PostgresStore) listEffectReconciliationCandidates(
	ctx context.Context,
	identity ConsumerIdentity,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
	commandVerifier EffectDispositionCommandVerifier,
) (contracts.EffectReconciliationCandidates, error) {
	if s == nil || s.db == nil || s.grantVerifier == nil || releaseAuthorities == nil || commandVerifier == nil {
		return contracts.EffectReconciliationCandidates{}, errors.New("effect reconciliation candidate store is not configured")
	}
	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return contracts.EffectReconciliationCandidates{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockApprovalScope(ctx, tx, identity.TenantID, identity.WorkspaceID); err != nil {
		return contracts.EffectReconciliationCandidates{}, err
	}

	fence, err := queryEffectDispositionFence(ctx, tx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.EffectReconciliationCandidates{}, ErrEffectDispositionRequiresFence
		}
		return contracts.EffectReconciliationCandidates{}, err
	}
	if err := verifyCurrentEffectReconciliationFence(fence); err != nil {
		return contracts.EffectReconciliationCandidates{}, err
	}

	reservations, err := queryCurrentEffectReconciliationReservations(ctx, tx, identity)
	if err != nil {
		return contracts.EffectReconciliationCandidates{}, err
	}
	projection := contracts.EffectReconciliationCandidates{
		SchemaVersion:      contracts.EffectReconciliationCandidatesSchemaV1,
		ContractVersion:    contracts.EffectReconciliationCandidatesContractV1,
		ExecutionAuthority: contracts.EffectDispositionExecutionAuthorityNone,
		TenantID:           identity.TenantID,
		WorkspaceID:        identity.WorkspaceID,
		Audience:           identity.Audience,
		Fence: contracts.EffectReconciliationFence{
			CommandID: fence.CommandID, CommandHash: fence.CommandHash,
			Epoch: fence.Epoch, ReceiptHash: fence.ReceiptHash,
		},
		Candidates: make([]contracts.EffectReconciliationCandidate, 0, len(reservations)),
	}
	for _, reservation := range reservations {
		if err := exactEffectReservationIdentity(reservation, identity); err != nil {
			return contracts.EffectReconciliationCandidates{}, err
		}
		if err := s.verifyEffectReservationAuthorities(reservation, releaseAuthorities); err != nil {
			return contracts.EffectReconciliationCandidates{}, err
		}
		candidate, eligible, err := effectReconciliationCandidateFromReservation(reservation)
		if err != nil {
			return contracts.EffectReconciliationCandidates{}, err
		}
		if !eligible {
			continue
		}
		chain, err := queryEffectDispositionRecordsForEffect(
			ctx, tx, identity.TenantID, identity.WorkspaceID, candidate.AdmissionID,
		)
		if err != nil {
			return contracts.EffectReconciliationCandidates{}, err
		}
		for index, record := range chain {
			if err := s.verifyEffectDispositionRecord(ctx, tx, identity, record, releaseAuthorities, commandVerifier); err != nil {
				return contracts.EffectReconciliationCandidates{}, err
			}
			if record.Receipt.DispositionSequence != uint64(index+1) {
				return contracts.EffectReconciliationCandidates{}, ErrEffectDispositionConflict
			}
		}
		candidate.NextDispositionSequence = uint64(len(chain) + 1)
		if len(chain) > 0 {
			candidate.PreviousReceiptHash = chain[len(chain)-1].Receipt.ReceiptHash
		}
		if err := candidate.Validate(); err != nil {
			return contracts.EffectReconciliationCandidates{}, err
		}
		projection.Candidates = append(projection.Candidates, candidate)
	}
	if err := projection.Validate(); err != nil {
		return contracts.EffectReconciliationCandidates{}, err
	}
	if err := tx.Commit(); err != nil {
		return contracts.EffectReconciliationCandidates{}, fmt.Errorf("commit effect reconciliation candidate listing: %w", err)
	}
	return projection, nil
}

func queryCurrentEffectReconciliationReservations(
	ctx context.Context,
	tx *sql.Tx,
	identity ConsumerIdentity,
) ([]EffectReservationEvent, error) {
	rows, err := tx.QueryContext(ctx, `WITH current_events AS (
		SELECT DISTINCT ON (admission_id) `+effectReservationColumns+`
		FROM approval_effect_reservation_events
		WHERE tenant_id = $1 AND workspace_id = $2
		ORDER BY admission_id, sequence DESC
	)
	SELECT `+effectReservationColumns+` FROM current_events
	WHERE state IN ('STARTED', 'UNCERTAIN')
	ORDER BY occurred_at, admission_id`, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return nil, fmt.Errorf("list effect reconciliation candidates: %w", err)
	}
	defer rows.Close()
	reservations := make([]EffectReservationEvent, 0)
	for rows.Next() {
		reservation, err := scanEffectReservationEvent(rows)
		if err != nil {
			return nil, err
		}
		reservations = append(reservations, reservation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate effect reconciliation candidates: %w", err)
	}
	return reservations, nil
}

func effectReconciliationCandidateFromReservation(
	reservation EffectReservationEvent,
) (contracts.EffectReconciliationCandidate, bool, error) {
	if err := reservation.Validate(); err != nil {
		return contracts.EffectReconciliationCandidate{}, false, err
	}
	if reservation.State != EffectReservationStateStarted && reservation.State != EffectReservationStateUncertain {
		return contracts.EffectReconciliationCandidate{}, false, nil
	}
	// UNCERTAIN is eligible only when its source record still has the immutable
	// references required by the later signed command. ADMITTED never reaches
	// this projection because it is a no-command/non-start state.
	if !validToken(reservation.ConnectorExecutionRef) || !validToken(reservation.IntentRef) {
		return contracts.EffectReconciliationCandidate{}, false, nil
	}
	headHash, err := effectReservationHeadHash(reservation)
	if err != nil {
		return contracts.EffectReconciliationCandidate{}, false, err
	}
	admission := reservation.Admission.Admission
	return contracts.EffectReconciliationCandidate{
		AdmissionID: admission.AdmissionID, AttemptID: admission.AttemptID,
		ReservationSequence: reservation.Sequence, ReservationHeadHash: headHash,
		ReservationState:      string(reservation.State),
		ConnectorID:           admission.ConnectorAuthority.ConnectorID,
		ConnectorVersion:      admission.ConnectorAuthority.ConnectorVersion,
		ConnectorAction:       admission.ConnectorAuthority.ConnectorAction,
		ConnectorExecutionRef: reservation.ConnectorExecutionRef,
		ProofSessionRef:       reservation.ProofSessionRef,
		IntentRef:             reservation.IntentRef,
		EffectRef:             reservation.EffectRef,
		IdempotencyKeyHash:    admission.IdempotencyKeyHash,
		EffectHash:            admission.EffectHash,
	}, true, nil
}

func verifyCurrentEffectReconciliationFence(fence kernel.FenceState) error {
	if !validToken(fence.TenantID) || !validToken(fence.WorkspaceID) || !validToken(fence.CommandID) ||
		!validSHA256(fence.CommandHash) || !validSHA256(fence.ReceiptHash) || fence.Epoch == 0 ||
		fence.Epoch > contracts.ConnectorReleaseAuthorityMaxRevision {
		return ErrEffectDispositionConflict
	}
	payload, err := fence.AcknowledgementPayload()
	if err != nil {
		return ErrEffectDispositionConflict
	}
	sum := sha256.Sum256(payload)
	if fence.ReceiptHash != "sha256:"+hex.EncodeToString(sum[:]) {
		return ErrEffectDispositionConflict
	}
	return nil
}
