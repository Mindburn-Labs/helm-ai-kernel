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
    expires_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    consumed_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, approval_id),
    CHECK (version > 0)
);

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
            USING (tenant_id = current_setting('app.current_tenant', true))
            WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
    END IF;
END
$$;
`

const recordColumns = `
approval_id, tenant_id, workspace_id, state, hold_started_at,
challenge_spec_json, challenge_json, verified_ref_json, grant_json,
grant_signature_algorithm, grant_signature,
created_at, updated_at, consumed_at, consumed_by, version
`

// PostgresStore is the production ceremony authority store. Every operation
// sets tenant context inside its transaction and repeats tenant_id in the SQL
// predicate, so RLS and application scoping fail closed together.
type PostgresStore struct {
	db            *sql.DB
	grantVerifier GrantSignatureVerifier
}

func NewPostgresStore(db *sql.DB, verifier GrantSignatureVerifier) *PostgresStore {
	return &PostgresStore{db: db, grantVerifier: verifier}
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
	return s.withTenantRecord(ctx, record.TenantID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
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

func (s *PostgresStore) Get(ctx context.Context, tenantID, approvalID string) (Record, error) {
	if !validToken(tenantID) || !validToken(approvalID) {
		return Record{}, invalidRecord("tenant_id and approval_id are required")
	}
	record, err := s.withTenantRecord(ctx, tenantID, ErrNotFound, func(tx *sql.Tx) rowScanner {
		return tx.QueryRowContext(ctx, `SELECT `+recordColumns+`
            FROM approval_ceremonies
            WHERE tenant_id = $1 AND approval_id = $2`, tenantID, approvalID)
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
	return record, nil
}

func (s *PostgresStore) issueChallenge(ctx context.Context, tenantID, approvalID string, challenge contracts.ApprovalChallenge, now time.Time) (Record, error) {
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
	return s.withTenantRecord(ctx, tenantID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
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
			challenge.Nonce, challenge.ExpiresAt, now.UTC(), challenge.WorkspaceID,
			challenge.HoldStartedAt,
		)
	})
}

func (s *PostgresStore) recordQuorum(ctx context.Context, tenantID, approvalID string, verified approvalverify.VerifiedApprovalRef, now time.Time) (Record, error) {
	if !verified.VerifiedAt.Equal(now.UTC()) {
		return Record{}, invalidRecord("verified_ref verified_at must be the server transition time")
	}
	payload, err := json.Marshal(verified)
	if err != nil {
		return Record{}, fmt.Errorf("marshal verified approval ref: %w", err)
	}
	return s.withTenantRecord(ctx, tenantID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
		return tx.QueryRowContext(ctx, `
            UPDATE approval_ceremonies
            SET state = $3, verified_ref_json = $4, signer_set_hash = $5,
                updated_at = $6, version = version + 1
            WHERE tenant_id = $1 AND approval_id = $2
			  AND state = 'CHALLENGE_ISSUED'
			  AND challenge_hash = $7
			  AND expires_at > $6
			  AND updated_at <= $6
            RETURNING `+recordColumns,
			tenantID, approvalID, StateQuorumVerified, payload, verified.SignerSetHash,
			now.UTC(), verified.ChallengeHash,
		)
	})
}

func (s *PostgresStore) issueGrant(ctx context.Context, tenantID, approvalID string, grant contracts.ApprovalGrant, algorithm, signature string, now time.Time) (Record, error) {
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
	return s.withTenantRecord(ctx, tenantID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
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
            RETURNING `+recordColumns,
			tenantID, approvalID, StateGrantIssued, payload, grant.GrantID,
			grant.GrantHash, grant.Nonce, algorithm, signature, grant.ExpiresAt,
			now.UTC(), grant.SignerSetHash,
		)
	})
}

func (s *PostgresStore) consumeGrant(ctx context.Context, tenantID, workspaceID, approvalID, grantID, grantHash, nonce, consumedBy string, now time.Time) (Record, error) {
	if !validToken(workspaceID) || !validToken(consumedBy) || !validToken(grantID) || !validSHA256(grantHash) || !validNonce(nonce) {
		return Record{}, invalidRecord("exact workspace, grant id, hash, nonce, and consumer are required")
	}
	if s == nil || s.db == nil {
		return Record{}, errors.New("approval ceremony postgres store requires database")
	}
	if s.grantVerifier == nil {
		return Record{}, fmt.Errorf("%w: verifier is not configured", ErrGrantSignatureRejected)
	}
	consumedAt := now.UTC()
	tx, err := s.beginTenantTx(ctx, tenantID)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback() }()

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
	if err := s.grantVerifier.VerifyGrantSignature(
		*issued.Grant, issued.GrantSignatureAlgorithm, issued.GrantSignature,
	); err != nil {
		return Record{}, err
	}

	consumed, err := scanRecord(tx.QueryRowContext(ctx, `
		UPDATE approval_ceremonies
		SET state = $3, consumed_at = $4, consumed_by = $5,
			updated_at = $4, version = version + 1
		WHERE tenant_id = $1 AND approval_id = $2
		  AND state = 'GRANT_ISSUED' AND version = $6
		  AND workspace_id = $7
		  AND grant_id = $8 AND grant_hash = $9 AND grant_nonce = $10
		  AND consumed_at IS NULL AND expires_at > $4 AND updated_at <= $4
		RETURNING `+recordColumns,
		tenantID, approvalID, StateConsumed, consumedAt, consumedBy, issued.Version,
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

func (s *PostgresStore) deny(ctx context.Context, tenantID, approvalID string, now time.Time) (Record, error) {
	return s.withTenantRecord(ctx, tenantID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
		return tx.QueryRowContext(ctx, `
            UPDATE approval_ceremonies
            SET state = $3, updated_at = $4, version = version + 1
			WHERE tenant_id = $1 AND approval_id = $2
			  AND state IN ('HOLD_PENDING', 'CHALLENGE_ISSUED', 'QUORUM_VERIFIED', 'GRANT_ISSUED')
			  AND updated_at <= $4
            RETURNING `+recordColumns,
			tenantID, approvalID, StateDenied, now.UTC(),
		)
	})
}

func (s *PostgresStore) expire(ctx context.Context, tenantID, approvalID string, now time.Time) (Record, error) {
	return s.withTenantRecord(ctx, tenantID, ErrTransitionConflict, func(tx *sql.Tx) rowScanner {
		return tx.QueryRowContext(ctx, `
            UPDATE approval_ceremonies
            SET state = $3, updated_at = $4, version = version + 1
            WHERE tenant_id = $1 AND approval_id = $2
			  AND state IN ('CHALLENGE_ISSUED', 'QUORUM_VERIFIED', 'GRANT_ISSUED')
			  AND expires_at <= $4
			  AND updated_at <= $4
            RETURNING `+recordColumns,
			tenantID, approvalID, StateExpired, now.UTC(),
		)
	})
}

type rowScanner interface {
	Scan(...any) error
}

func (s *PostgresStore) withTenantRecord(ctx context.Context, tenantID string, emptyError error, query func(*sql.Tx) rowScanner) (Record, error) {
	if s == nil || s.db == nil {
		return Record{}, errors.New("approval ceremony postgres store requires database")
	}
	tx, err := s.beginTenantTx(ctx, tenantID)
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

func (s *PostgresStore) beginTenantTx(ctx context.Context, tenantID string) (*sql.Tx, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("approval ceremony postgres store requires database")
	}
	if !validToken(tenantID) {
		return nil, invalidRecord("tenant_id is required")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin approval ceremony transaction: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set approval ceremony tenant: %w", err)
	}
	return tx, nil
}

func scanRecord(row rowScanner) (Record, error) {
	var record Record
	var state string
	var specJSON string
	var challengeJSON, verifiedJSON, grantJSON sql.NullString
	var signatureAlgorithm, signature, consumedBy sql.NullString
	var consumedAt sql.NullTime
	if err := row.Scan(
		&record.ApprovalID, &record.TenantID, &record.WorkspaceID, &state,
		&record.HoldStartedAt, &specJSON, &challengeJSON, &verifiedJSON, &grantJSON,
		&signatureAlgorithm, &signature, &record.CreatedAt, &record.UpdatedAt,
		&consumedAt, &consumedBy, &record.Version,
	); err != nil {
		return Record{}, err
	}
	record.State = State(state)
	record.GrantSignatureAlgorithm = signatureAlgorithm.String
	record.GrantSignature = signature.String
	record.ConsumedBy = consumedBy.String
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
	return record, nil
}

func validNonce(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
