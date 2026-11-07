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
connector_execution_ref, proof_session_ref, intent_ref, effect_ref,
close_prior_state, acknowledgement_hash, close_receipt_hash, outcome,
evidence_pack_ref, evidence_pack_hash, reconciliation_ref
`

// EffectReservationAdmitter owns the durable near-effect lifecycle. It keeps
// the signed dispatch admission immutable and records ordered connector-start
// truth in a separate append-only stream.
type EffectReservationAdmitter struct {
	store              *PostgresStore
	consumer           ConsumerIdentityProvider
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore
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
	var closePriorState, acknowledgementHash, closeReceiptHash, outcome sql.NullString
	var evidencePackRef, evidencePackHash, reconciliationRef sql.NullString
	if err := row.Scan(
		&tenantID, &workspaceID, &admissionID, &event.Sequence, &state,
		&attemptID, &approvalID, &grantID, &grantHash, &consumptionHash,
		&subject, &audience, &idempotencyKeyHash, &effectHash, &action, &connectorAction,
		&connectorID, &connectorVersion, &releaseScopeKind, &releaseAuthorityID,
		&releaseRegistryRevision, &releaseAuthorityHash, &event.ReleaseObservedAt,
		&admissionJSON, &releaseJSON, &event.AdmittedAt, &startedAt, &resolvedAt, &event.OccurredAt,
		&reasonCode, &connectorExecutionRef, &proofSessionRef, &intentRef, &effectRef,
		&closePriorState, &acknowledgementHash, &closeReceiptHash, &outcome,
		&evidencePackRef, &evidencePackHash, &reconciliationRef,
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
	event.ClosePriorState = closePriorState.String
	event.AcknowledgementHash = acknowledgementHash.String
	event.CloseReceiptHash = closeReceiptHash.String
	event.Outcome = outcome.String
	event.EvidencePackRef = evidencePackRef.String
	event.EvidencePackHash = evidencePackHash.String
	event.ReconciliationRef = reconciliationRef.String
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
