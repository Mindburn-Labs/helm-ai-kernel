package generatedspecapprovalceremony

// quantum_posture: this persistence layer stores and verifies the ceremony's
// classical Ed25519 envelopes. It does not make a hybrid or post-quantum claim.

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapproval"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

var ErrEmergencyStopFenced = errors.New("generated spec approval ceremony scope is emergency-stop fenced")

//go:embed migrations/001_generated_spec_approval_ceremonies.sql
var generatedSpecApprovalPostgresSchema string

const generatedSpecApprovalRecordColumns = `
approval_id, tenant_id, workspace_id, state, binding_json, hold_started_at,
challenge_json, assertions_json, quorum_verified_at, grant_json, consumption_json,
created_at, updated_at, expires_at, consumed_at, consumed_by, version
`

// PostgresStore is the durable Kernel-side ceremony store. It owns only
// persistence, RLS scoping, and atomic state transitions; it does not provide
// binding/authority identity, transport, Control Plane projection, or approval
// route activation.
type PostgresStore struct {
	db       *sql.DB
	verifier GrantSignatureVerifier
	clock    func() time.Time
}

func NewPostgresStore(db *sql.DB, verifier GrantSignatureVerifier) *PostgresStore {
	return &PostgresStore{db: db, verifier: verifier, clock: time.Now}
}

// Init installs this package's isolated schema. It intentionally does not
// initialize emergency_stop_fences: ConsumeGrant fails closed if that durable
// scoped-stop authority is not already present.
func (s *PostgresStore) Init(ctx context.Context) error {
	if err := s.requireReady(); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, generatedSpecApprovalPostgresSchema); err != nil {
		return fmt.Errorf("initialize generated spec approval ceremony schema: %w", err)
	}
	return nil
}

func (s *PostgresStore) CreateHold(ctx context.Context, record Record) (Record, error) {
	if err := s.requireReady(); err != nil {
		return Record{}, err
	}
	if record.State != StateHoldPending || record.Version != 1 || !record.CreatedAt.Equal(record.HoldStartedAt) || !record.UpdatedAt.Equal(record.HoldStartedAt) {
		return Record{}, invalidRecord("new ceremony must be a version-one HOLD_PENDING record")
	}
	if err := record.validate(); err != nil {
		return Record{}, err
	}
	bindingJSON, err := json.Marshal(record.Binding)
	if err != nil {
		return Record{}, fmt.Errorf("marshal generated spec approval binding: %w", err)
	}

	return s.withScopeTx(ctx, record.TenantID, record.WorkspaceID, func(tx *sql.Tx) (Record, error) {
		created, err := scanGeneratedSpecApprovalRecord(tx.QueryRowContext(ctx, `
			INSERT INTO generated_spec_approval_ceremonies (
				tenant_id, workspace_id, approval_id, state,
				binding_json, binding_ref, audience, generated_spec_id,
				generated_spec_hash, execution_plan_hash, plan_transaction_hash,
				write_set_hash, verification_scope_hash, policy_envelope_hash,
				policy_version, policy_epoch, action, requesting_principal_id,
				authority_source, authority_version, authority_snapshot_hash,
				required_role, quorum, server_identity,
				hold_started_at, created_at, updated_at, version
			) VALUES (
				$1, $2, $3, $4,
				$5, $6, $7, $8,
				$9, $10, $11,
				$12, $13, $14,
				$15, $16, $17, $18,
				$19, $20, $21,
				$22, $23, $24,
				$25, $26, $27, $28
			)
			ON CONFLICT (tenant_id, workspace_id, approval_id) DO NOTHING
			RETURNING `+generatedSpecApprovalRecordColumns,
			record.TenantID, record.WorkspaceID, record.ApprovalID, record.State,
			string(bindingJSON), record.Binding.BindingRef, record.Binding.Audience, record.Binding.GeneratedSpecID,
			record.Binding.GeneratedSpecHash, record.Binding.ExecutionPlanHash, record.Binding.PlanTransactionHash,
			record.Binding.WriteSetHash, record.Binding.VerificationScopeHash, record.Binding.PolicyEnvelopeHash,
			record.Binding.PolicyVersion, record.Binding.PolicyEpoch, record.Binding.Action, record.Binding.RequestingPrincipalID,
			record.Binding.AuthoritySource, record.Binding.AuthorityVersion, record.Binding.AuthoritySnapshotHash,
			record.Binding.RequiredRole, record.Binding.Quorum, record.Binding.ServerIdentity,
			record.HoldStartedAt, record.CreatedAt, record.UpdatedAt, record.Version,
		))
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrTransitionConflict
		}
		if err != nil {
			return Record{}, err
		}
		return s.validateLoaded(created)
	})
}

func (s *PostgresStore) Get(ctx context.Context, tenantID, workspaceID, approvalID string) (Record, error) {
	if err := s.requireReady(); err != nil {
		return Record{}, err
	}
	return s.withScopeTx(ctx, tenantID, workspaceID, func(tx *sql.Tx) (Record, error) {
		return s.loadRecord(ctx, tx, tenantID, workspaceID, approvalID, false)
	})
}

func (s *PostgresStore) IssueChallenge(ctx context.Context, tenantID, workspaceID, approvalID string, challenge contracts.GeneratedSpecApprovalChallenge, issuedAt time.Time) (Record, error) {
	if err := s.requireReady(); err != nil {
		return Record{}, err
	}
	issuedAt = issuedAt.UTC().Truncate(time.Microsecond)
	if !challenge.IssuedAt.Equal(issuedAt) {
		return Record{}, invalidRecord("challenge issued_at must be the server transition time")
	}
	if err := challenge.ValidateAt(issuedAt); err != nil {
		return Record{}, fmt.Errorf("validate generated spec approval challenge: %w", err)
	}

	return s.withScopeTx(ctx, tenantID, workspaceID, func(tx *sql.Tx) (Record, error) {
		current, err := s.loadRecord(ctx, tx, tenantID, workspaceID, approvalID, true)
		if err != nil {
			return Record{}, err
		}
		if current.State != StateHoldPending || !current.HoldStartedAt.Equal(challenge.HoldStartedAt) {
			return Record{}, ErrTransitionConflict
		}
		next := current
		next.State = StateChallengeIssued
		next.Challenge = &challenge
		expiresAt := challenge.ExpiresAt
		next.ExpiresAt = &expiresAt
		next.UpdatedAt = issuedAt
		next.Version++
		if err := next.validate(); err != nil {
			return Record{}, err
		}
		challengeJSON, err := json.Marshal(challenge)
		if err != nil {
			return Record{}, fmt.Errorf("marshal generated spec approval challenge: %w", err)
		}
		updated, err := scanGeneratedSpecApprovalRecord(tx.QueryRowContext(ctx, `
			UPDATE generated_spec_approval_ceremonies
			SET state = $4, challenge_json = $5, challenge_id = $6,
				challenge_hash = $7, challenge_nonce = $8, expires_at = $9,
				updated_at = $10, version = version + 1
			WHERE tenant_id = $1 AND workspace_id = $2 AND approval_id = $3
				AND state = 'HOLD_PENDING' AND version = $11
			RETURNING `+generatedSpecApprovalRecordColumns,
			tenantID, workspaceID, approvalID, StateChallengeIssued, string(challengeJSON),
			challenge.ChallengeID, challenge.ChallengeHash, challenge.Nonce, challenge.ExpiresAt,
			issuedAt, current.Version,
		))
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrTransitionConflict
		}
		if err != nil {
			return Record{}, err
		}
		return s.validateLoaded(updated)
	})
}

func (s *PostgresStore) RecordQuorum(ctx context.Context, tenantID, workspaceID, approvalID string, assertions []contracts.GeneratedSpecApprovalAssertion, verifiedAt time.Time) (Record, error) {
	if err := s.requireReady(); err != nil {
		return Record{}, err
	}
	verifiedAt = verifiedAt.UTC().Truncate(time.Microsecond)
	if len(assertions) == 0 {
		return Record{}, invalidRecord("quorum assertions are required")
	}

	return s.withScopeTx(ctx, tenantID, workspaceID, func(tx *sql.Tx) (Record, error) {
		current, err := s.loadRecord(ctx, tx, tenantID, workspaceID, approvalID, true)
		if err != nil {
			return Record{}, err
		}
		if current.State != StateChallengeIssued || current.Challenge == nil || len(assertions) < current.Binding.Quorum || !verifiedAt.Before(current.Challenge.ExpiresAt) {
			return Record{}, ErrTransitionConflict
		}
		if err := validateAssertionsForChallenge(assertions, *current.Challenge); err != nil {
			return Record{}, err
		}
		next := current
		next.State = StateQuorumVerified
		next.Assertions = append([]contracts.GeneratedSpecApprovalAssertion(nil), assertions...)
		next.QuorumVerifiedAt = &verifiedAt
		next.UpdatedAt = verifiedAt
		next.Version++
		if err := next.validate(); err != nil {
			return Record{}, err
		}
		assertionsJSON, err := json.Marshal(assertions)
		if err != nil {
			return Record{}, fmt.Errorf("marshal generated spec approval assertions: %w", err)
		}
		updated, err := scanGeneratedSpecApprovalRecord(tx.QueryRowContext(ctx, `
			UPDATE generated_spec_approval_ceremonies
			SET state = $4, assertions_json = $5, quorum_verified_at = $6,
				updated_at = $6, version = version + 1
			WHERE tenant_id = $1 AND workspace_id = $2 AND approval_id = $3
				AND state = 'CHALLENGE_ISSUED' AND version = $7
				AND challenge_hash = $8 AND expires_at > $6
			RETURNING `+generatedSpecApprovalRecordColumns,
			tenantID, workspaceID, approvalID, StateQuorumVerified, string(assertionsJSON),
			verifiedAt, current.Version, current.Challenge.ChallengeHash,
		))
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrTransitionConflict
		}
		if err != nil {
			return Record{}, err
		}
		return s.validateLoaded(updated)
	})
}

func (s *PostgresStore) IssueGrant(ctx context.Context, tenantID, workspaceID, approvalID string, signed generatedspecapproval.SignedGrant, verifier GrantSignatureVerifier, issuedAt time.Time) (Record, error) {
	if err := s.requireReady(); err != nil {
		return Record{}, err
	}
	issuedAt = issuedAt.UTC().Truncate(time.Microsecond)
	if verifier == nil || !signed.Grant.IssuedAt.Equal(issuedAt) || !issuedAt.Before(signed.Grant.ExpiresAt) {
		return Record{}, ErrTransitionConflict
	}
	if err := s.verifyGrant(signed, verifier, issuedAt); err != nil {
		return Record{}, err
	}

	return s.withScopeTx(ctx, tenantID, workspaceID, func(tx *sql.Tx) (Record, error) {
		current, err := s.loadRecord(ctx, tx, tenantID, workspaceID, approvalID, true)
		if err != nil {
			return Record{}, err
		}
		if current.State != StateQuorumVerified || current.Challenge == nil || current.QuorumVerifiedAt == nil || !issuedAt.Before(current.Challenge.ExpiresAt) {
			return Record{}, ErrTransitionConflict
		}
		next := current
		signedCopy := copySignedGrant(signed)
		next.State = StateGrantIssued
		next.SignedGrant = &signedCopy
		expiresAt := signed.Grant.ExpiresAt
		next.ExpiresAt = &expiresAt
		next.UpdatedAt = issuedAt
		next.Version++
		if err := next.validate(); err != nil {
			return Record{}, err
		}
		grantJSON, err := json.Marshal(signed)
		if err != nil {
			return Record{}, fmt.Errorf("marshal generated spec approval grant: %w", err)
		}
		updated, err := scanGeneratedSpecApprovalRecord(tx.QueryRowContext(ctx, `
			UPDATE generated_spec_approval_ceremonies
			SET state = $4, grant_json = $5, grant_id = $6, grant_hash = $7,
				grant_nonce = $8, grant_signature_algorithm = $9,
				grant_signature = $10, expires_at = $11, updated_at = $12,
				version = version + 1
			WHERE tenant_id = $1 AND workspace_id = $2 AND approval_id = $3
				AND state = 'QUORUM_VERIFIED' AND version = $13
				AND challenge_hash = $14 AND expires_at > $12
			RETURNING `+generatedSpecApprovalRecordColumns,
			tenantID, workspaceID, approvalID, StateGrantIssued, string(grantJSON),
			signed.Grant.GrantID, signed.Grant.GrantHash, signed.Grant.Nonce,
			signed.Algorithm, signed.Signature, signed.Grant.ExpiresAt, issuedAt,
			current.Version, current.Challenge.ChallengeHash,
		))
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrTransitionConflict
		}
		if err != nil {
			return Record{}, err
		}
		return s.validateLoaded(updated)
	})
}

func (s *PostgresStore) ConsumeGrant(ctx context.Context, tenantID, workspaceID, approvalID, grantID, grantHash, nonce, consumedBy, audience string, verifier GrantSignatureVerifier, requestedAt time.Time, seal ConsumptionSealer) (Record, error) {
	if err := s.requireReady(); err != nil {
		return Record{}, err
	}
	if verifier == nil || seal == nil || !validToken(grantID) || !validSHA256(grantHash) || !validToken(nonce) || !validToken(consumedBy) || !validToken(audience) {
		return Record{}, invalidRecord("exact grant, consumer, audience, verifier, and sealer are required")
	}

	return s.withScopeTx(ctx, tenantID, workspaceID, func(tx *sql.Tx) (Record, error) {
		if err := requireGeneratedSpecApprovalUnfencedScope(ctx, tx, tenantID, workspaceID); err != nil {
			return Record{}, err
		}
		consumedAt := s.transitionTime(requestedAt)
		current, err := s.loadRecord(ctx, tx, tenantID, workspaceID, approvalID, true)
		if err != nil {
			return Record{}, err
		}
		if current.State != StateGrantIssued || current.SignedGrant == nil || current.SignedGrant.Grant.GrantID != grantID ||
			current.SignedGrant.Grant.GrantHash != grantHash || current.SignedGrant.Grant.Nonce != nonce {
			return Record{}, ErrTransitionConflict
		}
		if current.SignedGrant.Grant.Audience != audience {
			return Record{}, fmt.Errorf("%w: signed grant workload scope mismatch", ErrConsumerUnavailable)
		}
		if err := ensureGrantActive(current.SignedGrant.Grant, consumedAt); err != nil {
			return Record{}, err
		}
		if err := s.verifyGrant(*current.SignedGrant, verifier, consumedAt); err != nil {
			return Record{}, err
		}
		signedConsumption, err := seal(copySignedGrant(*current.SignedGrant), consumedBy, consumedAt)
		if err != nil {
			return Record{}, err
		}
		if err := s.verifyConsumption(signedConsumption, *current.SignedGrant, verifier); err != nil {
			return Record{}, err
		}
		next := current
		consumptionCopy := copySignedConsumption(signedConsumption)
		next.State = StateConsumed
		next.SignedConsumption = &consumptionCopy
		next.ConsumedAt = &consumedAt
		next.ConsumedBy = consumedBy
		next.UpdatedAt = consumedAt
		next.Version++
		if err := next.validate(); err != nil {
			return Record{}, err
		}
		consumptionJSON, err := json.Marshal(signedConsumption)
		if err != nil {
			return Record{}, fmt.Errorf("marshal generated spec approval consumption: %w", err)
		}
		updated, err := scanGeneratedSpecApprovalRecord(tx.QueryRowContext(ctx, `
			UPDATE generated_spec_approval_ceremonies
			SET state = $4, consumption_json = $5, consumption_hash = $6,
				consumption_audience = $7, consumption_signature_algorithm = $8,
				consumption_signature = $9, consumed_at = $10, consumed_by = $11,
				updated_at = $10, version = version + 1
			WHERE tenant_id = $1 AND workspace_id = $2 AND approval_id = $3
				AND state = 'GRANT_ISSUED' AND version = $12
				AND grant_id = $13 AND grant_hash = $14 AND grant_nonce = $15
				AND expires_at > $10 AND consumed_at IS NULL
			RETURNING `+generatedSpecApprovalRecordColumns,
			tenantID, workspaceID, approvalID, StateConsumed, string(consumptionJSON),
			signedConsumption.Consumption.ConsumptionHash, signedConsumption.Consumption.Audience,
			signedConsumption.Algorithm, signedConsumption.Signature, consumedAt, consumedBy,
			current.Version, grantID, grantHash, nonce,
		))
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrTransitionConflict
		}
		if err != nil {
			return Record{}, err
		}
		return s.validateLoaded(updated)
	})
}

func (s *PostgresStore) Deny(ctx context.Context, tenantID, workspaceID, approvalID string, deniedAt time.Time) (Record, error) {
	if err := s.requireReady(); err != nil {
		return Record{}, err
	}
	deniedAt = deniedAt.UTC().Truncate(time.Microsecond)
	return s.withScopeTx(ctx, tenantID, workspaceID, func(tx *sql.Tx) (Record, error) {
		current, err := s.loadRecord(ctx, tx, tenantID, workspaceID, approvalID, true)
		if err != nil {
			return Record{}, err
		}
		switch current.State {
		case StateHoldPending, StateChallengeIssued, StateQuorumVerified, StateGrantIssued:
		default:
			return Record{}, ErrTransitionConflict
		}
		next := current
		next.State = StateDenied
		next.UpdatedAt = deniedAt
		next.Version++
		if err := next.validate(); err != nil {
			return Record{}, err
		}
		return s.updateTerminal(ctx, tx, current, StateDenied, deniedAt)
	})
}

func (s *PostgresStore) Expire(ctx context.Context, tenantID, workspaceID, approvalID string, expiredAt time.Time) (Record, error) {
	if err := s.requireReady(); err != nil {
		return Record{}, err
	}
	expiredAt = expiredAt.UTC().Truncate(time.Microsecond)
	return s.withScopeTx(ctx, tenantID, workspaceID, func(tx *sql.Tx) (Record, error) {
		current, err := s.loadRecord(ctx, tx, tenantID, workspaceID, approvalID, true)
		if err != nil {
			return Record{}, err
		}
		switch current.State {
		case StateChallengeIssued, StateQuorumVerified, StateGrantIssued:
		default:
			return Record{}, ErrTransitionConflict
		}
		if current.ExpiresAt == nil || expiredAt.Before(*current.ExpiresAt) {
			return Record{}, ErrTransitionConflict
		}
		next := current
		next.State = StateExpired
		next.UpdatedAt = expiredAt
		next.Version++
		if err := next.validate(); err != nil {
			return Record{}, err
		}
		return s.updateTerminal(ctx, tx, current, StateExpired, expiredAt)
	})
}

func (s *PostgresStore) updateTerminal(ctx context.Context, tx *sql.Tx, current Record, state State, updatedAt time.Time) (Record, error) {
	updated, err := scanGeneratedSpecApprovalRecord(tx.QueryRowContext(ctx, `
		UPDATE generated_spec_approval_ceremonies
		SET state = $4, updated_at = $5, version = version + 1
		WHERE tenant_id = $1 AND workspace_id = $2 AND approval_id = $3
			AND state = $6 AND version = $7
		RETURNING `+generatedSpecApprovalRecordColumns,
		current.TenantID, current.WorkspaceID, current.ApprovalID, state, updatedAt,
		current.State, current.Version,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrTransitionConflict
	}
	if err != nil {
		return Record{}, err
	}
	return s.validateLoaded(updated)
}

func (s *PostgresStore) withScopeTx(ctx context.Context, tenantID, workspaceID string, operation func(*sql.Tx) (Record, error)) (Record, error) {
	tx, err := s.beginScopeTx(ctx, tenantID, workspaceID)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	record, err := operation(tx)
	if err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fmt.Errorf("commit generated spec approval ceremony transaction: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) beginScopeTx(ctx context.Context, tenantID, workspaceID string) (*sql.Tx, error) {
	if err := s.requireReady(); err != nil {
		return nil, err
	}
	if !validToken(tenantID) || !validToken(workspaceID) {
		return nil, invalidRecord("tenant_id and workspace_id are required")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin generated spec approval ceremony transaction: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set generated spec approval ceremony tenant: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, workspaceID); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set generated spec approval ceremony workspace: %w", err)
	}
	return tx, nil
}

func (s *PostgresStore) loadRecord(ctx context.Context, tx *sql.Tx, tenantID, workspaceID, approvalID string, forUpdate bool) (Record, error) {
	if !validToken(approvalID) {
		return Record{}, invalidRecord("approval_id is required")
	}
	query := `SELECT ` + generatedSpecApprovalRecordColumns + `
		FROM generated_spec_approval_ceremonies
		WHERE tenant_id = $1 AND workspace_id = $2 AND approval_id = $3`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	record, err := scanGeneratedSpecApprovalRecord(tx.QueryRowContext(ctx, query, tenantID, workspaceID, approvalID))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	return s.validateLoaded(record)
}

func (s *PostgresStore) validateLoaded(record Record) (Record, error) {
	if err := record.validate(); err != nil {
		return Record{}, err
	}
	if err := validateAssertionsForRecord(record); err != nil {
		return Record{}, err
	}
	if record.SignedGrant != nil {
		if err := s.verifier.VerifyGrant(*record.SignedGrant, record.SignedGrant.Grant.IssuedAt); err != nil {
			return Record{}, err
		}
	}
	if record.SignedConsumption != nil {
		if record.SignedGrant == nil {
			return Record{}, invalidRecord("persisted consumption has no grant")
		}
		if err := s.verifier.VerifyConsumption(*record.SignedConsumption, *record.SignedGrant); err != nil {
			return Record{}, err
		}
	}
	return record, nil
}

func validateAssertionsForRecord(record Record) error {
	if len(record.Assertions) == 0 {
		return nil
	}
	if record.Challenge == nil {
		return invalidRecord("persisted assertions have no challenge")
	}
	return validateAssertionsForChallenge(record.Assertions, *record.Challenge)
}

func validateAssertionsForChallenge(assertions []contracts.GeneratedSpecApprovalAssertion, challenge contracts.GeneratedSpecApprovalChallenge) error {
	for _, assertion := range assertions {
		if err := assertion.Validate(); err != nil {
			return invalidRecord("persisted assertion: " + err.Error())
		}
		if assertion.ChallengeID != challenge.ChallengeID || assertion.ChallengeHash != challenge.ChallengeHash {
			return invalidRecord("persisted assertion does not match challenge")
		}
	}
	return nil
}

func (s *PostgresStore) verifyGrant(signed generatedspecapproval.SignedGrant, supplied GrantSignatureVerifier, at time.Time) error {
	if supplied == nil {
		return invalidRecord("grant verifier is required")
	}
	if err := supplied.VerifyGrant(signed, at); err != nil {
		return err
	}
	return s.verifier.VerifyGrant(signed, at)
}

func (s *PostgresStore) verifyConsumption(signed generatedspecapproval.SignedConsumption, grant generatedspecapproval.SignedGrant, supplied GrantSignatureVerifier) error {
	if supplied == nil {
		return invalidRecord("grant verifier is required")
	}
	if err := supplied.VerifyConsumption(signed, grant); err != nil {
		return err
	}
	return s.verifier.VerifyConsumption(signed, grant)
}

func (s *PostgresStore) requireReady() error {
	if s == nil || s.db == nil {
		return errors.New("generated spec approval ceremony postgres store requires database")
	}
	if s.verifier == nil {
		return errors.New("generated spec approval ceremony postgres store requires pinned verifier")
	}
	return nil
}

func (s *PostgresStore) transitionTime(fallback time.Time) time.Time {
	if s == nil || s.clock == nil {
		return fallback.UTC().Truncate(time.Microsecond)
	}
	return s.clock().UTC().Truncate(time.Microsecond)
}

func requireGeneratedSpecApprovalUnfencedScope(ctx context.Context, tx *sql.Tx, tenantID, workspaceID string) error {
	if tx == nil {
		return errors.New("generated spec approval ceremony scope transaction is unavailable")
	}
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, tenantID, workspaceID,
	); err != nil {
		return fmt.Errorf("coordinate generated spec approval consumption with emergency stop: %w", err)
	}
	var fenced bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM emergency_stop_fences
		WHERE tenant_id = $1 AND workspace_id = $2
	)`, tenantID, workspaceID).Scan(&fenced); err != nil {
		return fmt.Errorf("verify generated spec approval emergency-stop scope: %w", err)
	}
	if fenced {
		return ErrEmergencyStopFenced
	}
	return nil
}

type generatedSpecApprovalRowScanner interface {
	Scan(...any) error
}

func scanGeneratedSpecApprovalRecord(row generatedSpecApprovalRowScanner) (Record, error) {
	var record Record
	var state string
	var bindingJSON string
	var challengeJSON, assertionsJSON, grantJSON, consumptionJSON sql.NullString
	var quorumVerifiedAt, expiresAt, consumedAt sql.NullTime
	var consumedBy sql.NullString
	if err := row.Scan(
		&record.ApprovalID, &record.TenantID, &record.WorkspaceID, &state, &bindingJSON, &record.HoldStartedAt,
		&challengeJSON, &assertionsJSON, &quorumVerifiedAt, &grantJSON, &consumptionJSON,
		&record.CreatedAt, &record.UpdatedAt, &expiresAt, &consumedAt, &consumedBy, &record.Version,
	); err != nil {
		return Record{}, err
	}
	record.State = State(state)
	record.HoldStartedAt = record.HoldStartedAt.UTC()
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	record.ConsumedBy = consumedBy.String
	if err := json.Unmarshal([]byte(bindingJSON), &record.Binding); err != nil {
		return Record{}, fmt.Errorf("decode persisted generated spec approval binding: %w", err)
	}
	if challengeJSON.Valid {
		var challenge contracts.GeneratedSpecApprovalChallenge
		if err := json.Unmarshal([]byte(challengeJSON.String), &challenge); err != nil {
			return Record{}, fmt.Errorf("decode persisted generated spec approval challenge: %w", err)
		}
		record.Challenge = &challenge
	}
	if assertionsJSON.Valid {
		if err := json.Unmarshal([]byte(assertionsJSON.String), &record.Assertions); err != nil {
			return Record{}, fmt.Errorf("decode persisted generated spec approval assertions: %w", err)
		}
	}
	if quorumVerifiedAt.Valid {
		value := quorumVerifiedAt.Time.UTC()
		record.QuorumVerifiedAt = &value
	}
	if grantJSON.Valid {
		var signed generatedspecapproval.SignedGrant
		if err := json.Unmarshal([]byte(grantJSON.String), &signed); err != nil {
			return Record{}, fmt.Errorf("decode persisted generated spec approval grant: %w", err)
		}
		record.SignedGrant = &signed
	}
	if consumptionJSON.Valid {
		var signed generatedspecapproval.SignedConsumption
		if err := json.Unmarshal([]byte(consumptionJSON.String), &signed); err != nil {
			return Record{}, fmt.Errorf("decode persisted generated spec approval consumption: %w", err)
		}
		record.SignedConsumption = &signed
	}
	if expiresAt.Valid {
		value := expiresAt.Time.UTC()
		record.ExpiresAt = &value
	}
	if consumedAt.Valid {
		value := consumedAt.Time.UTC()
		record.ConsumedAt = &value
	}
	return record, nil
}

func copySignedGrant(signed generatedspecapproval.SignedGrant) generatedspecapproval.SignedGrant {
	copy := signed
	copy.Grant.ApproverPrincipalIDs = append([]string(nil), signed.Grant.ApproverPrincipalIDs...)
	return copy
}

func copySignedConsumption(signed generatedspecapproval.SignedConsumption) generatedspecapproval.SignedConsumption {
	copy := signed
	copy.Consumption.ApproverPrincipalIDs = append([]string(nil), signed.Consumption.ApproverPrincipalIDs...)
	return copy
}

var _ Store = (*PostgresStore)(nil)
