package approvalceremony

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const postgresSchema = `
CREATE TABLE IF NOT EXISTS approval_ceremonies (
    tenant_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    state TEXT NOT NULL,
    hold_started_at TIMESTAMPTZ NOT NULL,
    challenge_spec_json JSONB NOT NULL,
    challenge_json JSONB,
    challenge_hash TEXT,
    challenge_nonce TEXT,
    verified_ref_json JSONB,
    signer_set_hash TEXT,
    grant_json JSONB,
    grant_id TEXT,
    grant_hash TEXT,
    grant_nonce TEXT,
    grant_signature_algorithm TEXT,
    grant_signature TEXT,
    grant_consumption_json JSONB,
    consumption_signature_algorithm TEXT,
    consumption_signature TEXT,
    expires_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    consumed_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, approval_id),
    CHECK (version > 0)
);

ALTER TABLE approval_ceremonies
    ADD COLUMN IF NOT EXISTS grant_consumption_json JSONB,
    ADD COLUMN IF NOT EXISTS consumption_signature_algorithm TEXT,
    ADD COLUMN IF NOT EXISTS consumption_signature TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'approval_ceremonies'::regclass
          AND conname = 'approval_ceremonies_consumption_shape_ck'
    ) THEN
        ALTER TABLE approval_ceremonies
            ADD CONSTRAINT approval_ceremonies_consumption_shape_ck CHECK (
                (state = 'CONSUMED' AND consumed_at IS NOT NULL AND consumed_by IS NOT NULL
                    AND grant_consumption_json IS NOT NULL
                    AND consumption_signature_algorithm IS NOT NULL
                    AND consumption_signature IS NOT NULL)
                OR
                (state <> 'CONSUMED' AND consumed_at IS NULL AND consumed_by IS NULL
                    AND grant_consumption_json IS NULL
                    AND consumption_signature_algorithm IS NULL
                    AND consumption_signature IS NULL)
            );
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS approval_ceremonies_challenge_hash_uq
    ON approval_ceremonies (tenant_id, challenge_hash)
    WHERE challenge_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS approval_ceremonies_challenge_nonce_uq
    ON approval_ceremonies (tenant_id, challenge_nonce)
    WHERE challenge_nonce IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS approval_ceremonies_grant_id_uq
    ON approval_ceremonies (tenant_id, grant_id)
    WHERE grant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS approval_ceremonies_grant_hash_uq
    ON approval_ceremonies (tenant_id, grant_hash)
    WHERE grant_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS approval_ceremonies_grant_nonce_uq
    ON approval_ceremonies (tenant_id, grant_nonce)
    WHERE grant_nonce IS NOT NULL;

ALTER TABLE approval_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_ceremonies FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'approval_ceremonies'
          AND policyname = 'approval_ceremonies_tenant_isolation'
    ) THEN
        CREATE POLICY approval_ceremonies_tenant_isolation ON approval_ceremonies
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

ALTER POLICY approval_ceremonies_tenant_isolation ON approval_ceremonies
    USING (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant', true)
        AND workspace_id = current_setting('app.current_workspace', true)
    );
`

const recordColumns = `
approval_id, tenant_id, workspace_id, state, hold_started_at,
challenge_spec_json, challenge_json, verified_ref_json, grant_json,
grant_signature_algorithm, grant_signature,
grant_consumption_json, consumption_signature_algorithm, consumption_signature,
created_at, updated_at, expires_at, consumed_at, consumed_by, version
`

// PostgresStore is the production ceremony authority store. Every operation
// sets tenant and workspace context inside its transaction and repeats both in
// SQL predicates, so RLS and application scoping fail closed together.
type PostgresStore struct {
	db            *sql.DB
	grantVerifier GrantSignatureVerifier
	clock         func() time.Time
}

func NewPostgresStore(db *sql.DB, verifier GrantSignatureVerifier) *PostgresStore {
	return &PostgresStore{db: db, grantVerifier: verifier, clock: time.Now}
}

func (s *PostgresStore) transitionTime(fallback time.Time) time.Time {
	if s == nil || s.clock == nil {
		return fallback.UTC().Truncate(time.Microsecond)
	}
	return s.clock().UTC().Truncate(time.Microsecond)
}

func (s *PostgresStore) Init(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("approval ceremony postgres store requires database")
	}
	if s.grantVerifier == nil {
		return fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	if _, err := s.db.ExecContext(ctx, postgresSchema); err != nil {
		return fmt.Errorf("initialize approval ceremony schema: %w", err)
	}
	return nil
}

func (s *PostgresStore) createHold(ctx context.Context, record Record) (Record, error) {
	if record.State == "" {
		record.State = StateHoldPending
	}
	if record.Version == 0 {
		record.Version = 1
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = record.HoldStartedAt
	}
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = record.CreatedAt
	}
	if record.State != StateHoldPending {
		return Record{}, invalidRecord("new ceremony must start in HOLD_PENDING")
	}
	if !record.HoldStartedAt.Equal(record.CreatedAt) || !record.CreatedAt.Equal(record.UpdatedAt) {
		return Record{}, invalidRecord("new ceremony timestamps must equal the server hold time")
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	specJSON, err := json.Marshal(record.Spec)
	if err != nil {
		return Record{}, fmt.Errorf("marshal approval challenge spec: %w", err)
	}
	return s.withScopedRecord(ctx, record.TenantID, record.WorkspaceID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
		return tx.QueryRowContext(ctx, `
            INSERT INTO approval_ceremonies (
                tenant_id, approval_id, workspace_id, state, hold_started_at,
                challenge_spec_json, created_at, updated_at, version
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING `+recordColumns,
			record.TenantID, record.ApprovalID, record.WorkspaceID, record.State,
			record.HoldStartedAt, specJSON, record.CreatedAt, record.UpdatedAt, record.Version,
		)
	})
}

func (s *PostgresStore) get(ctx context.Context, tenantID, workspaceID, approvalID string) (Record, error) {
	if !validToken(tenantID) || !validToken(workspaceID) || !validToken(approvalID) {
		return Record{}, invalidRecord("tenant_id, workspace_id, and approval_id are required")
	}
	record, err := s.withScopedRecord(ctx, tenantID, workspaceID, ErrNotFound, func(tx *sql.Tx) rowScanner {
		return tx.QueryRowContext(ctx, `SELECT `+recordColumns+`
            FROM approval_ceremonies
			WHERE tenant_id = $1 AND workspace_id = $2 AND approval_id = $3`,
			tenantID, workspaceID, approvalID,
		)
	})
	if err != nil {
		return Record{}, err
	}
	if record.Grant != nil {
		if s.grantVerifier == nil {
			return Record{}, fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
		}
		if err := s.grantVerifier.VerifyGrantSignature(
			*record.Grant, record.GrantSignatureAlgorithm, record.GrantSignature,
		); err != nil {
			return Record{}, err
		}
	}
	if record.GrantConsumption != nil {
		if s.grantVerifier == nil {
			return Record{}, fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
		}
		if err := s.grantVerifier.VerifyGrantConsumptionSignature(
			*record.GrantConsumption, record.ConsumptionSignatureAlgorithm, record.ConsumptionSignature,
		); err != nil {
			return Record{}, err
		}
	}
	return record, nil
}

func (s *PostgresStore) issueChallenge(ctx context.Context, tenantID, workspaceID, approvalID string, challenge contracts.ApprovalChallenge, now time.Time) (Record, error) {
	if !challenge.IssuedAt.Equal(now.UTC()) {
		return Record{}, invalidRecord("challenge issued_at must be the server transition time")
	}
	if err := challenge.ValidateAt(now); err != nil {
		return Record{}, fmt.Errorf("issue approval challenge: %w", err)
	}
	payload, err := json.Marshal(challenge)
	if err != nil {
		return Record{}, fmt.Errorf("marshal approval challenge: %w", err)
	}
	return s.withScopedRecord(ctx, tenantID, workspaceID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
		return tx.QueryRowContext(ctx, `
            UPDATE approval_ceremonies
            SET state = $3, challenge_json = $4, challenge_hash = $5,
                challenge_nonce = $6, expires_at = $7, updated_at = $8,
                version = version + 1
			WHERE tenant_id = $1 AND approval_id = $2
			  AND state = 'HOLD_PENDING'
			  AND workspace_id = $9
			  AND hold_started_at = $10
			  AND updated_at <= $8
            RETURNING `+recordColumns,
			tenantID, approvalID, StateChallengeIssued, payload, challenge.ChallengeHash,
			challenge.Nonce, challenge.ExpiresAt, now.UTC(), workspaceID,
			challenge.HoldStartedAt,
		)
	})
}

func (s *PostgresStore) recordQuorum(ctx context.Context, tenantID, workspaceID, approvalID string, verified approvalverify.VerifiedApprovalRef, now time.Time) (Record, error) {
	if !verified.VerifiedAt.Equal(now.UTC()) {
		return Record{}, invalidRecord("verified_ref verified_at must be the server transition time")
	}
	payload, err := json.Marshal(verified)
	if err != nil {
		return Record{}, fmt.Errorf("marshal verified approval ref: %w", err)
	}
	return s.withScopedRecord(ctx, tenantID, workspaceID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
		return tx.QueryRowContext(ctx, `
            UPDATE approval_ceremonies
            SET state = $3, verified_ref_json = $4, signer_set_hash = $5,
                updated_at = $6, version = version + 1
            WHERE tenant_id = $1 AND approval_id = $2
			  AND state = 'CHALLENGE_ISSUED'
			  AND challenge_hash = $7
			  AND expires_at > $6
			  AND updated_at <= $6
			  AND workspace_id = $8
            RETURNING `+recordColumns,
			tenantID, approvalID, StateQuorumVerified, payload, verified.SignerSetHash,
			now.UTC(), verified.ChallengeHash, workspaceID,
		)
	})
}

func (s *PostgresStore) issueGrant(ctx context.Context, tenantID, workspaceID, approvalID string, grant contracts.ApprovalGrant, algorithm, signature string, now time.Time) (Record, error) {
	if !grant.IssuedAt.Equal(now.UTC()) {
		return Record{}, invalidRecord("grant issued_at must be the server transition time")
	}
	if err := grant.ValidateAt(now); err != nil {
		return Record{}, fmt.Errorf("issue approval grant: %w", err)
	}
	if algorithm != GrantSignatureEd25519 || !validEd25519Signature(signature) {
		return Record{}, invalidRecord("valid ed25519 grant signature is required")
	}
	if s == nil || s.grantVerifier == nil {
		return Record{}, fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	if err := s.grantVerifier.VerifyGrantSignature(grant, algorithm, signature); err != nil {
		return Record{}, err
	}
	payload, err := json.Marshal(grant)
	if err != nil {
		return Record{}, fmt.Errorf("marshal approval grant: %w", err)
	}
	return s.withScopedRecord(ctx, tenantID, workspaceID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
		return tx.QueryRowContext(ctx, `
            UPDATE approval_ceremonies
            SET state = $3, grant_json = $4, grant_id = $5, grant_hash = $6,
                grant_nonce = $7, grant_signature_algorithm = $8,
                grant_signature = $9, expires_at = $10, updated_at = $11,
                version = version + 1
            WHERE tenant_id = $1 AND approval_id = $2
			  AND state = 'QUORUM_VERIFIED'
			  AND signer_set_hash = $12
			  AND expires_at > $11
			  AND updated_at <= $11
			  AND workspace_id = $13
            RETURNING `+recordColumns,
			tenantID, approvalID, StateGrantIssued, payload, grant.GrantID,
			grant.GrantHash, grant.Nonce, algorithm, signature, grant.ExpiresAt,
			now.UTC(), grant.SignerSetHash, workspaceID,
		)
	})
}

func (s *PostgresStore) consumeGrant(ctx context.Context, tenantID, workspaceID, approvalID, grantID, grantHash, nonce string, sealConsumption grantConsumptionSealer, requestedAt time.Time) (Record, error) {
	if !validToken(workspaceID) || !validToken(grantID) || !validSHA256(grantHash) || !validNonce(nonce) || sealConsumption == nil {
		return Record{}, invalidRecord("exact workspace, grant id, hash, nonce, consumer, and audience are required")
	}
	if s == nil || s.db == nil {
		return Record{}, errors.New("approval ceremony postgres store requires database")
	}
	if s.grantVerifier == nil {
		return Record{}, fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	tx, err := s.beginScopeTx(ctx, tenantID, workspaceID)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requireUnfencedScope(ctx, tx, tenantID, workspaceID); err != nil {
		return Record{}, err
	}
	consumedAt := s.transitionTime(requestedAt)

	issued, err := scanRecord(tx.QueryRowContext(ctx, `SELECT `+recordColumns+`
		FROM approval_ceremonies
		WHERE tenant_id = $1 AND approval_id = $2
		  AND workspace_id = $3
		  AND state = 'GRANT_ISSUED'
		  AND grant_id = $4 AND grant_hash = $5 AND grant_nonce = $6
		  AND consumed_at IS NULL AND expires_at > $7 AND updated_at <= $7
		FOR UPDATE`, tenantID, approvalID, workspaceID, grantID, grantHash, nonce, consumedAt))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrTransitionConflict
		}
		return Record{}, err
	}
	if err := issued.Validate(); err != nil {
		return Record{}, err
	}
	if issued.Grant == nil {
		return Record{}, invalidRecord("grant issued record is missing grant")
	}
	if err := issued.Grant.ValidateAt(consumedAt); err != nil {
		return Record{}, fmt.Errorf("%w: signed grant is inactive: %v", ErrTransitionConflict, err)
	}
	if err := s.grantVerifier.VerifyGrantSignature(
		*issued.Grant, issued.GrantSignatureAlgorithm, issued.GrantSignature,
	); err != nil {
		return Record{}, err
	}
	consumption, algorithm, signature, err := sealConsumption(*issued.Grant, consumedAt)
	if err != nil {
		return Record{}, err
	}
	if !validToken(consumption.ConsumedBy) || !validToken(consumption.Audience) || !consumption.ConsumedAt.Equal(consumedAt) {
		return Record{}, invalidRecord("consumption identity, audience, and server transition time are required")
	}
	if err := consumption.ValidateGrant(*issued.Grant); err != nil {
		return Record{}, err
	}
	if err := s.grantVerifier.VerifyGrantConsumptionSignature(consumption, algorithm, signature); err != nil {
		return Record{}, err
	}
	consumptionJSON, err := json.Marshal(consumption)
	if err != nil {
		return Record{}, fmt.Errorf("marshal approval grant consumption: %w", err)
	}

	consumed, err := scanRecord(tx.QueryRowContext(ctx, `
		UPDATE approval_ceremonies
		SET state = $3, consumed_at = $4, consumed_by = $5,
			grant_consumption_json = $6, consumption_signature_algorithm = $7,
			consumption_signature = $8,
			updated_at = $4, version = version + 1
		WHERE tenant_id = $1 AND approval_id = $2
		  AND state = 'GRANT_ISSUED' AND version = $9
		  AND workspace_id = $10
		  AND grant_id = $11 AND grant_hash = $12 AND grant_nonce = $13
		  AND consumed_at IS NULL AND expires_at > $4 AND updated_at <= $4
		RETURNING `+recordColumns,
		tenantID, approvalID, StateConsumed, consumedAt, consumption.ConsumedBy,
		consumptionJSON, algorithm, signature, issued.Version,
		workspaceID, grantID, grantHash, nonce,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrTransitionConflict
		}
		return Record{}, err
	}
	if err := consumed.Validate(); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fmt.Errorf("commit approval ceremony transaction: %w", err)
	}
	return consumed, nil
}

// requireUnfencedScope shares the same transaction-scoped advisory lock as
// the PostgreSQL emergency-stop store. Whichever transaction acquires the
// tenant/workspace lock first defines the ordering: a committed FENCE blocks
// consumption, while a committed consumption predates a later FENCE. The
// connector dispatch is a separate data-plane step and may not have begun.
func requireUnfencedScope(ctx context.Context, tx *sql.Tx, tenantID, workspaceID string) error {
	if tx == nil {
		return errors.New("approval ceremony scope transaction is unavailable")
	}
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`,
		tenantID, workspaceID,
	); err != nil {
		return fmt.Errorf("coordinate approval consumption with emergency stop: %w", err)
	}
	var fenced bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM emergency_stop_fences
		WHERE tenant_id = $1 AND workspace_id = $2
	)`, tenantID, workspaceID).Scan(&fenced); err != nil {
		return fmt.Errorf("verify approval consumption emergency-stop scope: %w", err)
	}
	if fenced {
		return ErrEmergencyStopFenced
	}
	return nil
}

func (s *PostgresStore) deny(ctx context.Context, tenantID, workspaceID, approvalID string, now time.Time) (Record, error) {
	return s.withScopedRecord(ctx, tenantID, workspaceID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
		return tx.QueryRowContext(ctx, `
            UPDATE approval_ceremonies
            SET state = $3, updated_at = $4, version = version + 1
			WHERE tenant_id = $1 AND approval_id = $2
			  AND state IN ('HOLD_PENDING', 'CHALLENGE_ISSUED', 'QUORUM_VERIFIED', 'GRANT_ISSUED')
			  AND updated_at <= $4
			  AND workspace_id = $5
            RETURNING `+recordColumns,
			tenantID, approvalID, StateDenied, now.UTC(), workspaceID,
		)
	})
}

func (s *PostgresStore) expire(ctx context.Context, tenantID, workspaceID, approvalID string, now time.Time) (Record, error) {
	return s.withScopedRecord(ctx, tenantID, workspaceID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
		return tx.QueryRowContext(ctx, `
            UPDATE approval_ceremonies
            SET state = $3, updated_at = $4, version = version + 1
            WHERE tenant_id = $1 AND approval_id = $2
			  AND state IN ('CHALLENGE_ISSUED', 'QUORUM_VERIFIED', 'GRANT_ISSUED')
			  AND expires_at <= $4
			  AND updated_at <= $4
			  AND workspace_id = $5
            RETURNING `+recordColumns,
			tenantID, approvalID, StateExpired, now.UTC(), workspaceID,
		)
	})
}

type rowScanner interface {
	Scan(...any) error
}

func (s *PostgresStore) withScopedRecord(ctx context.Context, tenantID, workspaceID string, emptyError error, query func(*sql.Tx) rowScanner) (Record, error) {
	if s == nil || s.db == nil {
		return Record{}, errors.New("approval ceremony postgres store requires database")
	}
	tx, err := s.beginScopeTx(ctx, tenantID, workspaceID)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := scanRecord(query(tx))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, emptyError
		}
		return Record{}, err
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fmt.Errorf("commit approval ceremony transaction: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) beginScopeTx(ctx context.Context, tenantID, workspaceID string) (*sql.Tx, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("approval ceremony postgres store requires database")
	}
	if !validToken(tenantID) || !validToken(workspaceID) {
		return nil, invalidRecord("tenant_id and workspace_id are required")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin approval ceremony transaction: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set approval ceremony tenant: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, workspaceID); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set approval ceremony workspace: %w", err)
	}
	return tx, nil
}

func scanRecord(row rowScanner) (Record, error) {
	var record Record
	var state string
	var specJSON string
	var challengeJSON, verifiedJSON, grantJSON, consumptionJSON sql.NullString
	var signatureAlgorithm, signature, consumptionAlgorithm, consumptionSignature, consumedBy sql.NullString
	var expiresAt, consumedAt sql.NullTime
	if err := row.Scan(
		&record.ApprovalID, &record.TenantID, &record.WorkspaceID, &state,
		&record.HoldStartedAt, &specJSON, &challengeJSON, &verifiedJSON, &grantJSON,
		&signatureAlgorithm, &signature, &consumptionJSON, &consumptionAlgorithm, &consumptionSignature,
		&record.CreatedAt, &record.UpdatedAt,
		&expiresAt, &consumedAt, &consumedBy, &record.Version,
	); err != nil {
		return Record{}, err
	}
	record.State = State(state)
	record.GrantSignatureAlgorithm = signatureAlgorithm.String
	record.GrantSignature = signature.String
	record.ConsumptionSignatureAlgorithm = consumptionAlgorithm.String
	record.ConsumptionSignature = consumptionSignature.String
	record.ConsumedBy = consumedBy.String
	if expiresAt.Valid {
		value := expiresAt.Time.UTC()
		record.ExpiresAt = &value
	}
	if err := json.Unmarshal([]byte(specJSON), &record.Spec); err != nil {
		return Record{}, fmt.Errorf("decode persisted approval challenge spec: %w", err)
	}
	if consumedAt.Valid {
		value := consumedAt.Time.UTC()
		record.ConsumedAt = &value
	}
	if challengeJSON.Valid {
		var challenge contracts.ApprovalChallenge
		if err := json.Unmarshal([]byte(challengeJSON.String), &challenge); err != nil {
			return Record{}, fmt.Errorf("decode persisted approval challenge: %w", err)
		}
		record.Challenge = &challenge
	}
	if verifiedJSON.Valid {
		var verified approvalverify.VerifiedApprovalRef
		if err := json.Unmarshal([]byte(verifiedJSON.String), &verified); err != nil {
			return Record{}, fmt.Errorf("decode persisted verified approval ref: %w", err)
		}
		record.VerifiedRef = &verified
	}
	if grantJSON.Valid {
		var grant contracts.ApprovalGrant
		if err := json.Unmarshal([]byte(grantJSON.String), &grant); err != nil {
			return Record{}, fmt.Errorf("decode persisted approval grant: %w", err)
		}
		record.Grant = &grant
	}
	if consumptionJSON.Valid {
		var consumption contracts.ApprovalGrantConsumption
		if err := json.Unmarshal([]byte(consumptionJSON.String), &consumption); err != nil {
			return Record{}, fmt.Errorf("decode persisted approval grant consumption: %w", err)
		}
		record.GrantConsumption = &consumption
	}
	return record, nil
}

func validNonce(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
