package approvalceremony

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const dispatchAdmissionPostgresSchema = `
CREATE TABLE IF NOT EXISTS approval_dispatch_admissions (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    consumption_hash TEXT NOT NULL,
    idempotency_key_hash TEXT NOT NULL,
    effect_hash TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    action TEXT NOT NULL,
    admitted_by TEXT NOT NULL,
    state TEXT NOT NULL,
    admission_json JSONB NOT NULL,
    signature_algorithm TEXT NOT NULL,
    signature TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, attempt_id),
    CHECK (state = 'NOT_STARTED'),
    CHECK (expires_at > issued_at),
    CHECK (created_at = issued_at),
    CHECK (updated_at = created_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS approval_dispatch_admissions_consumption_uq
    ON approval_dispatch_admissions (tenant_id, workspace_id, consumption_hash);

ALTER TABLE approval_dispatch_admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_dispatch_admissions FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'approval_dispatch_admissions'
          AND policyname = 'approval_dispatch_admissions_tenant_isolation'
    ) THEN
        CREATE POLICY approval_dispatch_admissions_tenant_isolation ON approval_dispatch_admissions
            USING (
                tenant_id = current_setting('app.current_tenant', true)
                AND workspace_id = current_setting('app.current_workspace', true)
            )
            WITH CHECK (
                tenant_id = current_setting('app.current_tenant', true)
                AND workspace_id = current_setting('app.current_workspace', true)
            );
    END IF;
END
$$;

ALTER POLICY approval_dispatch_admissions_tenant_isolation ON approval_dispatch_admissions
    USING (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    );
`

const dispatchAdmissionColumns = `
tenant_id, workspace_id, attempt_id, approval_id, consumption_hash,
idempotency_key_hash, effect_hash, connector_id, action, admitted_by, state,
issued_at, expires_at, admission_json, signature_algorithm, signature,
created_at, updated_at
`

func (s *PostgresStore) claimDispatchAdmission(ctx context.Context, identity ConsumerIdentity, request DispatchAdmissionRequest, seal dispatchAdmissionSealer, requestedAt time.Time) (DispatchAdmissionRecord, error) {
	if err := validateDispatchAdmissionInputs(identity, request); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	if seal == nil {
		return DispatchAdmissionRecord{}, invalidRecord("dispatch admission sealer is required")
	}
	if s == nil || s.db == nil {
		return DispatchAdmissionRecord{}, errors.New("approval ceremony postgres store requires database")
	}
	if s.grantVerifier == nil {
		return DispatchAdmissionRecord{}, fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return DispatchAdmissionRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockApprovalScope(ctx, tx, identity.TenantID, identity.WorkspaceID); err != nil {
		return DispatchAdmissionRecord{}, err
	}

	existing, err := scanDispatchAdmission(tx.QueryRowContext(ctx, `SELECT `+dispatchAdmissionColumns+`
		FROM approval_dispatch_admissions
		WHERE tenant_id = $1 AND workspace_id = $2 AND attempt_id = $3`,
		identity.TenantID, identity.WorkspaceID, request.AttemptID,
	))
	if err == nil {
		if err := s.validateDispatchAdmissionRecord(existing, identity, request); err != nil {
			return DispatchAdmissionRecord{}, err
		}
		if err := tx.Commit(); err != nil {
			return DispatchAdmissionRecord{}, fmt.Errorf("commit dispatch admission replay: %w", err)
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return DispatchAdmissionRecord{}, err
	}
	fenced, err := approvalScopeFenced(ctx, tx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return DispatchAdmissionRecord{}, err
	}
	if fenced {
		return DispatchAdmissionRecord{}, ErrEmergencyStopFenced
	}

	var consumedElsewhere bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM approval_dispatch_admissions
		WHERE tenant_id = $1 AND workspace_id = $2 AND consumption_hash = $3
	)`, identity.TenantID, identity.WorkspaceID, request.ConsumptionHash).Scan(&consumedElsewhere); err != nil {
		return DispatchAdmissionRecord{}, fmt.Errorf("check consumed grant dispatch uniqueness: %w", err)
	}
	if consumedElsewhere {
		return DispatchAdmissionRecord{}, ErrTransitionConflict
	}

	issuedAt := s.transitionTime(requestedAt)
	consumed, err := scanRecord(tx.QueryRowContext(ctx, `SELECT `+recordColumns+`
		FROM approval_ceremonies
		WHERE tenant_id = $1 AND workspace_id = $2 AND approval_id = $3
		  AND state = 'CONSUMED'
		  AND grant_consumption_json->>'consumption_hash' = $4
		  AND expires_at > $5
		FOR UPDATE`, identity.TenantID, identity.WorkspaceID, request.ApprovalID,
		request.ConsumptionHash, issuedAt,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DispatchAdmissionRecord{}, ErrTransitionConflict
		}
		return DispatchAdmissionRecord{}, err
	}
	if err := consumed.Validate(); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	if consumed.GrantConsumption == nil {
		return DispatchAdmissionRecord{}, invalidRecord("consumed ceremony is missing grant consumption")
	}
	if err := s.grantVerifier.VerifyGrantConsumptionSignature(
		*consumed.GrantConsumption, consumed.ConsumptionSignatureAlgorithm, consumed.ConsumptionSignature,
	); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	admission, algorithm, signature, err := seal(*consumed.GrantConsumption, issuedAt)
	if err != nil {
		return DispatchAdmissionRecord{}, err
	}
	if err := admission.ValidateConsumption(*consumed.GrantConsumption); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	if err := dispatchAdmissionMatches(admission, identity, request); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	if err := s.grantVerifier.VerifyDispatchAdmissionSignature(admission, algorithm, signature); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	payload, err := json.Marshal(admission)
	if err != nil {
		return DispatchAdmissionRecord{}, fmt.Errorf("marshal dispatch admission: %w", err)
	}
	created, err := scanDispatchAdmission(tx.QueryRowContext(ctx, `
		INSERT INTO approval_dispatch_admissions (
			tenant_id, workspace_id, attempt_id, approval_id, consumption_hash,
			idempotency_key_hash, effect_hash, connector_id, action, admitted_by,
			state, admission_json, signature_algorithm, signature,
			issued_at, expires_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $15, $15
		)
		RETURNING `+dispatchAdmissionColumns,
		identity.TenantID, identity.WorkspaceID, request.AttemptID, request.ApprovalID,
		request.ConsumptionHash, request.IdempotencyKeyHash, request.EffectHash,
		admission.ConnectorAuthority.ConnectorID, request.Action, identity.Subject, admission.State,
		payload, algorithm, signature, admission.IssuedAt, admission.ExpiresAt,
	))
	if err != nil {
		return DispatchAdmissionRecord{}, fmt.Errorf("persist dispatch admission: %w", err)
	}
	if err := s.validateDispatchAdmissionRecord(created, identity, request); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return DispatchAdmissionRecord{}, fmt.Errorf("commit dispatch admission: %w", err)
	}
	return created, nil
}

func (s *PostgresStore) recoverDispatchAdmission(ctx context.Context, identity ConsumerIdentity, request DispatchAdmissionRequest) (DispatchAdmissionRecord, error) {
	if err := validateDispatchAdmissionInputs(identity, request); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	tx, err := s.beginScopeTx(ctx, identity.TenantID, identity.WorkspaceID)
	if err != nil {
		return DispatchAdmissionRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := scanDispatchAdmission(tx.QueryRowContext(ctx, `SELECT `+dispatchAdmissionColumns+`
		FROM approval_dispatch_admissions
		WHERE tenant_id = $1 AND workspace_id = $2 AND attempt_id = $3`,
		identity.TenantID, identity.WorkspaceID, request.AttemptID,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DispatchAdmissionRecord{}, ErrNotFound
		}
		return DispatchAdmissionRecord{}, err
	}
	if err := s.validateDispatchAdmissionRecord(record, identity, request); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return DispatchAdmissionRecord{}, fmt.Errorf("commit dispatch admission recovery: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) validateDispatchAdmissionRecord(record DispatchAdmissionRecord, identity ConsumerIdentity, request DispatchAdmissionRequest) error {
	if err := record.Validate(); err != nil {
		return err
	}
	if err := dispatchAdmissionMatches(record.Admission, identity, request); err != nil {
		return err
	}
	if s == nil || s.grantVerifier == nil {
		return fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	return s.grantVerifier.VerifyDispatchAdmissionSignature(
		record.Admission, record.SignatureAlgorithm, record.Signature,
	)
}

func validateDispatchAdmissionInputs(identity ConsumerIdentity, request DispatchAdmissionRequest) error {
	if !validToken(identity.Subject) || !validToken(identity.TenantID) ||
		!validToken(identity.WorkspaceID) || !validToken(identity.Audience) {
		return fmt.Errorf("%w: verified workload subject, tenant, workspace, and audience are required", ErrConsumerUnavailable)
	}
	return request.Validate()
}

func dispatchAdmissionMatches(admission contracts.ApprovalDispatchAdmission, identity ConsumerIdentity, request DispatchAdmissionRequest) error {
	if admission.TenantID != identity.TenantID || admission.WorkspaceID != identity.WorkspaceID ||
		admission.Audience != identity.Audience || admission.AdmittedBy != identity.Subject {
		return fmt.Errorf("%w: persisted dispatch admission workload scope mismatch", ErrConsumerUnavailable)
	}
	if admission.ApprovalID != request.ApprovalID || admission.AttemptID != request.AttemptID ||
		admission.ConsumptionHash != request.ConsumptionHash || admission.IdempotencyKeyHash != request.IdempotencyKeyHash ||
		admission.EffectHash != request.EffectHash || admission.Action != request.Action {
		return ErrTransitionConflict
	}
	return nil
}

func scanDispatchAdmission(row rowScanner) (DispatchAdmissionRecord, error) {
	var record DispatchAdmissionRecord
	var payload string
	var tenantID, workspaceID, attemptID, approvalID, consumptionHash string
	var idempotencyKeyHash, effectHash, connectorID, action, admittedBy, state string
	var issuedAt, expiresAt time.Time
	if err := row.Scan(
		&tenantID, &workspaceID, &attemptID, &approvalID, &consumptionHash,
		&idempotencyKeyHash, &effectHash, &connectorID, &action, &admittedBy, &state,
		&issuedAt, &expiresAt, &payload, &record.SignatureAlgorithm, &record.Signature,
		&record.CreatedAt, &record.UpdatedAt,
	); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	if err := json.Unmarshal([]byte(payload), &record.Admission); err != nil {
		return DispatchAdmissionRecord{}, fmt.Errorf("decode persisted dispatch admission: %w", err)
	}
	issuedAt = issuedAt.UTC()
	expiresAt = expiresAt.UTC()
	if tenantID != record.Admission.TenantID || workspaceID != record.Admission.WorkspaceID ||
		attemptID != record.Admission.AttemptID || approvalID != record.Admission.ApprovalID ||
		consumptionHash != record.Admission.ConsumptionHash || idempotencyKeyHash != record.Admission.IdempotencyKeyHash ||
		effectHash != record.Admission.EffectHash || connectorID != record.Admission.ConnectorAuthority.ConnectorID ||
		action != record.Admission.Action || admittedBy != record.Admission.AdmittedBy ||
		state != record.Admission.State || !issuedAt.Equal(record.Admission.IssuedAt) ||
		!expiresAt.Equal(record.Admission.ExpiresAt) {
		return DispatchAdmissionRecord{}, invalidRecord("dispatch admission storage shadow mismatch")
	}
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}
