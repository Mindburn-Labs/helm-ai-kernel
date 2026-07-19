package approvalceremony

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	connectorregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry/connectors"
)

const effectReservationColumns = `
tenant_id, workspace_id, admission_id, sequence, state,
attempt_id, approval_id, grant_id, grant_hash, consumption_hash,
consumer_subject, audience, idempotency_key_hash, effect_hash, action, connector_action,
connector_id, connector_version, release_scope_kind, release_authority_id,
release_registry_revision, release_authority_hash, release_observed_at,
admission_json, release_authority_json,
admitted_at, started_at, resolved_at, occurred_at, reason_code,
connector_execution_ref, proof_session_ref, intent_ref, effect_ref
`

// EffectReservationAdmitter owns the durable near-effect lifecycle. It keeps
// the signed dispatch admission immutable and records ordered connector-start
// truth in a separate append-only stream.
type EffectReservationAdmitter struct {
	store              *PostgresStore
	consumer           ConsumerIdentityProvider
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore
}

func NewEffectReservationAdmitter(
	store *PostgresStore,
	consumer ConsumerIdentityProvider,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
) (*EffectReservationAdmitter, error) {
	if store == nil || consumer == nil || releaseAuthorities == nil {
		return nil, errors.New("approval effect reservation dependencies are required")
	}
	return &EffectReservationAdmitter{store: store, consumer: consumer, releaseAuthorities: releaseAuthorities}, nil
}

func (s *EffectReservationAdmitter) Admit(ctx context.Context, admission DispatchAdmissionRecord) (EffectReservationEvent, error) {
	if s == nil || s.store == nil || s.releaseAuthorities == nil {
		return EffectReservationEvent{}, errors.New("approval effect reservation admitter is not initialized")
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return EffectReservationEvent{}, err
	}
	return s.store.admitEffectReservation(ctx, identity, admission, s.releaseAuthorities)
}

func (s *EffectReservationAdmitter) Recover(ctx context.Context, admissionID string) (EffectReservationEvent, error) {
	if s == nil || s.store == nil {
		return EffectReservationEvent{}, errors.New("approval effect reservation admitter is not initialized")
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return EffectReservationEvent{}, err
	}
	return s.store.recoverEffectReservation(ctx, identity, admissionID, s.releaseAuthorities)
}

func (s *EffectReservationAdmitter) MarkStarted(ctx context.Context, admissionID string, meta EffectTransitionMeta) (EffectReservationEvent, error) {
	return s.transition(ctx, admissionID, EffectReservationStateStarted, meta)
}

func (s *EffectReservationAdmitter) MarkNotStarted(ctx context.Context, admissionID string, meta EffectTransitionMeta) (EffectReservationEvent, error) {
	return s.transition(ctx, admissionID, EffectReservationStateNotStarted, meta)
}

func (s *EffectReservationAdmitter) MarkUncertain(ctx context.Context, admissionID string, meta EffectTransitionMeta) (EffectReservationEvent, error) {
	return s.transition(ctx, admissionID, EffectReservationStateUncertain, meta)
}

func (s *EffectReservationAdmitter) transition(ctx context.Context, admissionID string, state EffectReservationState, meta EffectTransitionMeta) (EffectReservationEvent, error) {
	if s == nil || s.store == nil {
		return EffectReservationEvent{}, errors.New("approval effect reservation admitter is not initialized")
	}
	if err := validateEffectTransitionMeta(meta); err != nil {
		return EffectReservationEvent{}, err
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return EffectReservationEvent{}, err
	}
	return s.store.transitionEffectReservation(ctx, identity, admissionID, state, meta, s.releaseAuthorities)
}

func (s *EffectReservationAdmitter) ListActive(ctx context.Context) ([]EffectReservationEvent, error) {
	if s == nil || s.store == nil {
		return nil, errors.New("approval effect reservation admitter is not initialized")
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return nil, err
	}
	return s.store.listActiveEffectReservations(ctx, identity, s.releaseAuthorities)
}

func (s *PostgresStore) admitEffectReservation(
	ctx context.Context,
	identity ConsumerIdentity,
	provided DispatchAdmissionRecord,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
) (EffectReservationEvent, error) {
	if s == nil || s.db == nil || s.grantVerifier == nil || releaseAuthorities == nil {
		return EffectReservationEvent{}, errors.New("approval effect reservation store is not configured")
	}
	if err := provided.Validate(); err != nil {
		return EffectReservationEvent{}, err
	}
	if err := effectReservationMatchesIdentity(provided.Admission, identity); err != nil {
		return EffectReservationEvent{}, err
	}
	if err := s.grantVerifier.VerifyDispatchAdmissionSignature(provided.Admission, provided.SignatureAlgorithm, provided.Signature); err != nil {
		return EffectReservationEvent{}, err
	}

	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return EffectReservationEvent{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockApprovalScope(ctx, tx, identity.TenantID, identity.WorkspaceID); err != nil {
		return EffectReservationEvent{}, err
	}

	existing, err := queryCurrentEffectReservation(ctx, tx, identity.TenantID, identity.WorkspaceID, provided.Admission.AdmissionID)
	if err == nil {
		if err := exactEffectReservationAdmission(existing, provided, identity); err != nil {
			return EffectReservationEvent{}, err
		}
		if err := s.verifyEffectReservationAuthorities(existing, releaseAuthorities); err != nil {
			return EffectReservationEvent{}, err
		}
		if err := tx.Commit(); err != nil {
			return EffectReservationEvent{}, fmt.Errorf("commit effect reservation replay: %w", err)
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return EffectReservationEvent{}, err
	}

	fenced, err := approvalScopeFenced(ctx, tx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return EffectReservationEvent{}, err
	}
	if fenced {
		return EffectReservationEvent{}, ErrEmergencyStopFenced
	}

	persisted, err := scanDispatchAdmission(tx.QueryRowContext(ctx, `SELECT `+dispatchAdmissionColumns+`
		FROM approval_dispatch_admissions
		WHERE tenant_id = $1 AND workspace_id = $2 AND attempt_id = $3`,
		identity.TenantID, identity.WorkspaceID, provided.Admission.AttemptID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EffectReservationEvent{}, ErrNotFound
		}
		return EffectReservationEvent{}, err
	}
	if err := exactDispatchAdmissionRecord(persisted, provided); err != nil {
		return EffectReservationEvent{}, err
	}
	if err := s.grantVerifier.VerifyDispatchAdmissionSignature(persisted.Admission, persisted.SignatureAlgorithm, persisted.Signature); err != nil {
		return EffectReservationEvent{}, err
	}

	authority := persisted.Admission.ConnectorAuthority
	lookup := connectorregistry.ReleaseAuthorityLookup{
		ScopeKind: authority.ReleaseScopeKind, ConnectorID: authority.ConnectorID, ConnectorVersion: authority.ConnectorVersion,
	}
	if authority.ReleaseScopeKind == contracts.ConnectorReleaseAuthorityScopeWorkspace {
		lookup.TenantID = identity.TenantID
		lookup.WorkspaceID = identity.WorkspaceID
	}
	release, observedAt, err := releaseAuthorities.LockCurrentCertifiedForEffectAdmission(ctx, tx, lookup)
	if err != nil {
		return EffectReservationEvent{}, err
	}
	if err := persisted.Admission.ValidateAt(observedAt); err != nil {
		return EffectReservationEvent{}, err
	}
	if err := authority.ValidateCurrentRelease(release.Authority); err != nil {
		return EffectReservationEvent{}, err
	}

	event := EffectReservationEvent{
		Sequence: 1, State: EffectReservationStateAdmitted,
		Admission: persisted, ReleaseAuthority: release, ReleaseObservedAt: observedAt,
		AdmittedAt: observedAt, OccurredAt: observedAt,
	}
	created, err := insertEffectReservationEvent(ctx, tx, event)
	if err != nil {
		return EffectReservationEvent{}, err
	}
	if err := tx.Commit(); err != nil {
		return EffectReservationEvent{}, fmt.Errorf("commit effect reservation admission: %w", err)
	}
	return created, nil
}

func (s *PostgresStore) recoverEffectReservation(
	ctx context.Context,
	identity ConsumerIdentity,
	admissionID string,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
) (EffectReservationEvent, error) {
	if !validToken(admissionID) || len(admissionID) > 512 {
		return EffectReservationEvent{}, invalidRecord("effect reservation admission_id is invalid")
	}
	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return EffectReservationEvent{}, err
	}
	defer func() { _ = tx.Rollback() }()
	event, err := queryCurrentEffectReservation(ctx, tx, identity.TenantID, identity.WorkspaceID, admissionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EffectReservationEvent{}, ErrNotFound
		}
		return EffectReservationEvent{}, err
	}
	if err := exactEffectReservationIdentity(event, identity); err != nil {
		return EffectReservationEvent{}, err
	}
	if err := s.verifyEffectReservationAuthorities(event, releaseAuthorities); err != nil {
		return EffectReservationEvent{}, err
	}
	if err := tx.Commit(); err != nil {
		return EffectReservationEvent{}, fmt.Errorf("commit effect reservation recovery: %w", err)
	}
	return event, nil
}

func (s *PostgresStore) transitionEffectReservation(
	ctx context.Context,
	identity ConsumerIdentity,
	admissionID string,
	state EffectReservationState,
	meta EffectTransitionMeta,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
) (EffectReservationEvent, error) {
	if !validToken(admissionID) || len(admissionID) > 512 {
		return EffectReservationEvent{}, invalidRecord("effect reservation admission_id is invalid")
	}
	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return EffectReservationEvent{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockApprovalScope(ctx, tx, identity.TenantID, identity.WorkspaceID); err != nil {
		return EffectReservationEvent{}, err
	}
	current, err := queryCurrentEffectReservation(ctx, tx, identity.TenantID, identity.WorkspaceID, admissionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EffectReservationEvent{}, ErrNotFound
		}
		return EffectReservationEvent{}, err
	}
	if err := exactEffectReservationIdentity(current, identity); err != nil {
		return EffectReservationEvent{}, err
	}
	if err := s.verifyEffectReservationAuthorities(current, releaseAuthorities); err != nil {
		return EffectReservationEvent{}, err
	}
	if current.State == state {
		if state == EffectReservationStateStarted {
			return current, ErrEffectReservationAlreadyStarted
		}
		if effectTransitionMetaMatches(current, meta) {
			if err := tx.Commit(); err != nil {
				return EffectReservationEvent{}, fmt.Errorf("commit effect transition replay: %w", err)
			}
			return current, nil
		}
		return EffectReservationEvent{}, ErrEffectReservationConflict
	}
	if current.State == EffectReservationStateNotStarted || current.State == EffectReservationStateUncertain {
		return EffectReservationEvent{}, ErrEffectReservationTerminal
	}
	if current.State == EffectReservationStateStarted && state != EffectReservationStateUncertain {
		return EffectReservationEvent{}, ErrEffectReservationTerminal
	}
	if current.State == EffectReservationStateAdmitted &&
		state != EffectReservationStateStarted && state != EffectReservationStateNotStarted && state != EffectReservationStateUncertain {
		return EffectReservationEvent{}, ErrEffectReservationConflict
	}
	var now time.Time
	if state == EffectReservationStateStarted {
		fenced, fenceErr := approvalScopeFenced(ctx, tx, identity.TenantID, identity.WorkspaceID)
		if fenceErr != nil {
			return EffectReservationEvent{}, effectReservationStartDenied(fenceErr)
		}
		if fenced {
			return EffectReservationEvent{}, effectReservationStartDenied(ErrEmergencyStopFenced)
		}
		authority := current.Admission.Admission.ConnectorAuthority
		lookup := connectorregistry.ReleaseAuthorityLookup{
			ScopeKind: authority.ReleaseScopeKind, ConnectorID: authority.ConnectorID, ConnectorVersion: authority.ConnectorVersion,
		}
		if authority.ReleaseScopeKind == contracts.ConnectorReleaseAuthorityScopeWorkspace {
			lookup.TenantID = identity.TenantID
			lookup.WorkspaceID = identity.WorkspaceID
		}
		currentRelease, observedAt, releaseErr := releaseAuthorities.LockCurrentCertifiedForEffectAdmission(ctx, tx, lookup)
		if releaseErr != nil {
			return EffectReservationEvent{}, effectReservationStartDenied(releaseErr)
		}
		if releaseErr := authority.ValidateCurrentRelease(currentRelease.Authority); releaseErr != nil {
			return EffectReservationEvent{}, effectReservationStartDenied(releaseErr)
		}
		now = observedAt
		if !now.Before(current.Admission.Admission.ExpiresAt) {
			return EffectReservationEvent{}, effectReservationStartDenied(fmt.Errorf(
				"%w: dispatch admission expired before connector start", ErrEffectReservationConflict,
			))
		}
	} else {
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return EffectReservationEvent{}, fmt.Errorf("read effect transition database clock: %w", err)
		}
		now = now.UTC().Truncate(time.Microsecond)
	}
	if current.State == EffectReservationStateStarted && state == EffectReservationStateUncertain {
		var mergeErr error
		meta.ConnectorExecutionRef, mergeErr = preserveEffectReference(current.ConnectorExecutionRef, meta.ConnectorExecutionRef, false)
		if mergeErr == nil {
			meta.ProofSessionRef, mergeErr = preserveEffectReference(current.ProofSessionRef, meta.ProofSessionRef, false)
		}
		if mergeErr == nil {
			meta.IntentRef, mergeErr = preserveEffectReference(current.IntentRef, meta.IntentRef, false)
		}
		if mergeErr == nil {
			meta.EffectRef, mergeErr = preserveEffectReference(current.EffectRef, meta.EffectRef, true)
		}
		if mergeErr != nil {
			return EffectReservationEvent{}, mergeErr
		}
	}

	next := current
	next.Sequence++
	next.State = state
	next.OccurredAt = now
	next.ReasonCode = meta.ReasonCode
	next.ConnectorExecutionRef = meta.ConnectorExecutionRef
	next.ProofSessionRef = meta.ProofSessionRef
	next.IntentRef = meta.IntentRef
	next.EffectRef = meta.EffectRef
	switch state {
	case EffectReservationStateStarted:
		next.StartedAt = timePointer(now)
		next.ResolvedAt = nil
	case EffectReservationStateNotStarted:
		next.StartedAt = nil
		next.ResolvedAt = timePointer(now)
	case EffectReservationStateUncertain:
		next.ResolvedAt = timePointer(now)
	}
	created, err := insertEffectReservationEvent(ctx, tx, next)
	if err != nil {
		return EffectReservationEvent{}, err
	}
	if err := tx.Commit(); err != nil {
		return EffectReservationEvent{}, fmt.Errorf("commit effect reservation transition: %w", err)
	}
	return created, nil
}

func preserveEffectReference(existing, proposed string, allowAddition bool) (string, error) {
	if proposed == "" {
		return existing, nil
	}
	if (existing == "" && !allowAddition) || (existing != "" && proposed != existing) {
		return "", ErrEffectReservationConflict
	}
	return proposed, nil
}

func effectReservationStartDenied(cause error) error {
	return errors.Join(ErrEffectReservationStartDenied, cause)
}

func (s *PostgresStore) listActiveEffectReservations(
	ctx context.Context,
	identity ConsumerIdentity,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
) ([]EffectReservationEvent, error) {
	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `WITH current_events AS (
		SELECT DISTINCT ON (admission_id) `+effectReservationColumns+`
		FROM approval_effect_reservation_events
		WHERE tenant_id = $1 AND workspace_id = $2
		ORDER BY admission_id, sequence DESC
	)
	SELECT `+effectReservationColumns+` FROM current_events
	WHERE state IN ('ADMITTED', 'STARTED', 'UNCERTAIN')
	ORDER BY occurred_at, admission_id`, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return nil, fmt.Errorf("list active effect reservations: %w", err)
	}
	defer rows.Close()
	var events []EffectReservationEvent
	for rows.Next() {
		event, scanErr := scanEffectReservationEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		if err := exactEffectReservationIdentity(event, identity); err != nil {
			return nil, err
		}
		if err := s.verifyEffectReservationAuthorities(event, releaseAuthorities); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active effect reservations: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit active effect reservation listing: %w", err)
	}
	return events, nil
}

func (s *PostgresStore) verifyEffectReservationAuthorities(
	event EffectReservationEvent,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
) error {
	if s == nil || s.grantVerifier == nil || releaseAuthorities == nil {
		return errors.New("effect reservation authority verifiers are not configured")
	}
	if err := s.grantVerifier.VerifyDispatchAdmissionSignature(
		event.Admission.Admission, event.Admission.SignatureAlgorithm, event.Admission.Signature,
	); err != nil {
		return err
	}
	return releaseAuthorities.VerifyEnvelope(event.ReleaseAuthority)
}

func insertEffectReservationEvent(ctx context.Context, tx *sql.Tx, event EffectReservationEvent) (EffectReservationEvent, error) {
	if err := event.Validate(); err != nil {
		return EffectReservationEvent{}, err
	}
	admissionJSON, err := json.Marshal(event.Admission)
	if err != nil {
		return EffectReservationEvent{}, fmt.Errorf("marshal effect reservation admission: %w", err)
	}
	releaseJSON, err := json.Marshal(event.ReleaseAuthority)
	if err != nil {
		return EffectReservationEvent{}, fmt.Errorf("marshal effect reservation release authority: %w", err)
	}
	a := event.Admission.Admission
	ra := event.ReleaseAuthority.Authority
	return scanEffectReservationEvent(tx.QueryRowContext(ctx, `INSERT INTO approval_effect_reservation_events (
		tenant_id, workspace_id, admission_id, sequence, state,
		attempt_id, approval_id, grant_id, grant_hash, consumption_hash,
		consumer_subject, audience, idempotency_key_hash, effect_hash, action, connector_action,
		connector_id, connector_version, release_scope_kind, release_authority_id,
		release_registry_revision, release_authority_hash, release_observed_at,
		admission_json, release_authority_json,
		admitted_at, started_at, resolved_at, occurred_at, reason_code,
		connector_execution_ref, proof_session_ref, intent_ref, effect_ref
	) VALUES (
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,
		$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34
	) RETURNING `+effectReservationColumns,
		a.TenantID, a.WorkspaceID, a.AdmissionID, event.Sequence, event.State,
		a.AttemptID, a.ApprovalID, a.GrantID, a.GrantHash, a.ConsumptionHash,
		a.AdmittedBy, a.Audience, a.IdempotencyKeyHash, a.EffectHash, a.Action, a.ConnectorAuthority.ConnectorAction,
		ra.ConnectorID, ra.ConnectorVersion, ra.ScopeKind, ra.AuthorityID,
		ra.RegistryRevision, ra.AuthorityHash, event.ReleaseObservedAt,
		admissionJSON, releaseJSON, event.AdmittedAt, event.StartedAt, event.ResolvedAt,
		event.OccurredAt, nullableToken(event.ReasonCode), nullableToken(event.ConnectorExecutionRef),
		nullableToken(event.ProofSessionRef), nullableToken(event.IntentRef), nullableToken(event.EffectRef)))
}

func queryCurrentEffectReservation(ctx context.Context, tx *sql.Tx, tenantID, workspaceID, admissionID string) (EffectReservationEvent, error) {
	return scanEffectReservationEvent(tx.QueryRowContext(ctx, `SELECT `+effectReservationColumns+`
		FROM approval_effect_reservation_events
		WHERE tenant_id = $1 AND workspace_id = $2 AND admission_id = $3
		ORDER BY sequence DESC LIMIT 1`, tenantID, workspaceID, admissionID))
}

func scanEffectReservationEvent(row rowScanner) (EffectReservationEvent, error) {
	var event EffectReservationEvent
	var tenantID, workspaceID, admissionID, state string
	var attemptID, approvalID, grantID, grantHash, consumptionHash string
	var subject, audience, idempotencyKeyHash, effectHash, action, connectorAction string
	var connectorID, connectorVersion, releaseScopeKind, releaseAuthorityID, releaseAuthorityHash string
	var releaseRegistryRevision uint64
	var admissionJSON, releaseJSON []byte
	var startedAt, resolvedAt sql.NullTime
	var reasonCode, connectorExecutionRef, proofSessionRef, intentRef, effectRef sql.NullString
	if err := row.Scan(
		&tenantID, &workspaceID, &admissionID, &event.Sequence, &state,
		&attemptID, &approvalID, &grantID, &grantHash, &consumptionHash,
		&subject, &audience, &idempotencyKeyHash, &effectHash, &action, &connectorAction,
		&connectorID, &connectorVersion, &releaseScopeKind, &releaseAuthorityID,
		&releaseRegistryRevision, &releaseAuthorityHash, &event.ReleaseObservedAt,
		&admissionJSON, &releaseJSON, &event.AdmittedAt, &startedAt, &resolvedAt, &event.OccurredAt,
		&reasonCode, &connectorExecutionRef, &proofSessionRef, &intentRef, &effectRef,
	); err != nil {
		return EffectReservationEvent{}, err
	}
	if err := json.Unmarshal(admissionJSON, &event.Admission); err != nil {
		return EffectReservationEvent{}, fmt.Errorf("decode effect reservation admission: %w", err)
	}
	if err := json.Unmarshal(releaseJSON, &event.ReleaseAuthority); err != nil {
		return EffectReservationEvent{}, fmt.Errorf("decode effect reservation release authority: %w", err)
	}
	event.State = EffectReservationState(state)
	event.ReleaseObservedAt = event.ReleaseObservedAt.UTC()
	event.AdmittedAt = event.AdmittedAt.UTC()
	event.OccurredAt = event.OccurredAt.UTC()
	if startedAt.Valid {
		event.StartedAt = timePointer(startedAt.Time.UTC())
	}
	if resolvedAt.Valid {
		event.ResolvedAt = timePointer(resolvedAt.Time.UTC())
	}
	event.ReasonCode = reasonCode.String
	event.ConnectorExecutionRef = connectorExecutionRef.String
	event.ProofSessionRef = proofSessionRef.String
	event.IntentRef = intentRef.String
	event.EffectRef = effectRef.String
	a := event.Admission.Admission
	ra := event.ReleaseAuthority.Authority
	if tenantID != a.TenantID || workspaceID != a.WorkspaceID || admissionID != a.AdmissionID ||
		attemptID != a.AttemptID || approvalID != a.ApprovalID || grantID != a.GrantID ||
		grantHash != a.GrantHash || consumptionHash != a.ConsumptionHash || subject != a.AdmittedBy ||
		audience != a.Audience || idempotencyKeyHash != a.IdempotencyKeyHash || effectHash != a.EffectHash ||
		action != a.Action || connectorAction != a.ConnectorAuthority.ConnectorAction ||
		connectorID != ra.ConnectorID || connectorVersion != ra.ConnectorVersion ||
		releaseScopeKind != ra.ScopeKind || releaseAuthorityID != ra.AuthorityID ||
		releaseRegistryRevision != ra.RegistryRevision || releaseAuthorityHash != ra.AuthorityHash {
		return EffectReservationEvent{}, invalidRecord("effect reservation storage shadow mismatch")
	}
	if err := event.Validate(); err != nil {
		return EffectReservationEvent{}, err
	}
	return event, nil
}

func exactDispatchAdmissionRecord(persisted, provided DispatchAdmissionRecord) error {
	if persisted.Admission.AdmissionHash != provided.Admission.AdmissionHash ||
		persisted.SignatureAlgorithm != provided.SignatureAlgorithm || persisted.Signature != provided.Signature ||
		!persisted.CreatedAt.Equal(provided.CreatedAt) || !persisted.UpdatedAt.Equal(provided.UpdatedAt) {
		return ErrEffectReservationConflict
	}
	return nil
}

func exactEffectReservationAdmission(event EffectReservationEvent, provided DispatchAdmissionRecord, identity ConsumerIdentity) error {
	if err := exactEffectReservationIdentity(event, identity); err != nil {
		return err
	}
	return exactDispatchAdmissionRecord(event.Admission, provided)
}

func exactEffectReservationIdentity(event EffectReservationEvent, identity ConsumerIdentity) error {
	if err := event.Validate(); err != nil {
		return err
	}
	return effectReservationMatchesIdentity(event.Admission.Admission, identity)
}

func effectReservationMatchesIdentity(admission contracts.ApprovalDispatchAdmission, identity ConsumerIdentity) error {
	if admission.TenantID != identity.TenantID || admission.WorkspaceID != identity.WorkspaceID ||
		admission.AdmittedBy != identity.Subject || admission.Audience != identity.Audience {
		return fmt.Errorf("%w: effect reservation workload scope mismatch", ErrConsumerUnavailable)
	}
	return nil
}

func effectTransitionMetaMatches(event EffectReservationEvent, meta EffectTransitionMeta) bool {
	return event.ReasonCode == meta.ReasonCode && event.ConnectorExecutionRef == meta.ConnectorExecutionRef &&
		event.ProofSessionRef == meta.ProofSessionRef && event.IntentRef == meta.IntentRef && event.EffectRef == meta.EffectRef
}

func nullableToken(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func timePointer(value time.Time) *time.Time {
	value = value.UTC().Truncate(time.Microsecond)
	return &value
}
