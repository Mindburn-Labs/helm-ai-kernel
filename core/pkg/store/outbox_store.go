package store

import (
	"context"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effectdigest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor"
)

// PostgresEffectOutboxStore implements executor.OutboxStore
type PostgresEffectOutboxStore struct {
	db       *sql.DB
	verifier crypto.Verifier
}

func NewPostgresEffectOutboxStore(db *sql.DB, verifier crypto.Verifier) *PostgresEffectOutboxStore {
	return &PostgresEffectOutboxStore{db: db, verifier: verifier}
}

// Init creates the durable single-dispatch reservation ledger. It must be run
// before a SafeExecutor is allowed to dispatch an effect against this store.
func (s *PostgresEffectOutboxStore) Init(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS effect_outbox (
			id TEXT PRIMARY KEY,
			effect_json JSONB NOT NULL,
			decision_json JSONB NOT NULL,
			scheduled_at TIMESTAMPTZ NOT NULL,
			status TEXT NOT NULL,
			claim_token TEXT,
			claimed_at TIMESTAMPTZ,
			completed_at TIMESTAMPTZ
		);
		ALTER TABLE effect_outbox ADD COLUMN IF NOT EXISTS claim_token TEXT;
		ALTER TABLE effect_outbox ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;
		ALTER TABLE effect_outbox ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
		CREATE INDEX IF NOT EXISTS idx_effect_outbox_status_scheduled ON effect_outbox(status, scheduled_at);
	`)
	if err != nil {
		return fmt.Errorf("initialize effect outbox: %w", err)
	}
	return nil
}

// Schedule is retained for legacy asynchronous workers. It intentionally does
// not authorize direct execution: SafeExecutor uses Claim below, which owns a
// single durable dispatch reservation. New callers should never call Schedule
// immediately before a driver invocation.
func (s *PostgresEffectOutboxStore) Schedule(ctx context.Context, effect *contracts.Effect, intent *contracts.AuthorizedExecutionIntent) error {
	effectJSON, intentJSON, err := s.validateAndMarshal(effect, intent)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO effect_outbox (id, effect_json, decision_json, scheduled_at, status)
		VALUES ($1, $2, $3, $4, 'PENDING')
		ON CONFLICT (id) DO NOTHING
	`
	_, err = s.db.ExecContext(ctx, query, intent.ID, effectJSON, intentJSON, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to schedule effect: %w", err)
	}
	return nil
}

// Claim atomically reserves a signed intent before any ToolDriver invocation.
// Existing claims are never stolen or retried automatically: after a process
// crash or ambiguous connector error, an operator must reconcile the receipt
// and outbox state rather than risk dispatching an irreversible effect twice.
func (s *PostgresEffectOutboxStore) Claim(ctx context.Context, effect *contracts.Effect, intent *contracts.AuthorizedExecutionIntent) (executor.OutboxClaimResult, error) {
	effectJSON, intentJSON, err := s.validateAndMarshal(effect, intent)
	if err != nil {
		return executor.OutboxClaimResult{}, err
	}
	claimToken, err := newClaimToken()
	if err != nil {
		return executor.OutboxClaimResult{}, err
	}

	// ON CONFLICT DO UPDATE locks the existing row and returns its durable
	// state. The random claim token distinguishes ownership of a newly-inserted
	// reservation from a pre-existing CLAIMED row without relying on timing or
	// process-local state.
	query := `
		INSERT INTO effect_outbox (id, effect_json, decision_json, scheduled_at, status, claim_token, claimed_at)
		VALUES ($1, $2, $3, $4, 'CLAIMED', $5, $4)
		ON CONFLICT (id) DO UPDATE SET id = effect_outbox.id
		RETURNING status, claim_token
	`
	var status, storedToken string
	if err := s.db.QueryRowContext(ctx, query, intent.ID, effectJSON, intentJSON, time.Now().UTC(), claimToken).Scan(&status, &storedToken); err != nil {
		return executor.OutboxClaimResult{}, fmt.Errorf("claim effect dispatch: %w", err)
	}

	switch status {
	case "CLAIMED":
		if storedToken == claimToken {
			return executor.OutboxClaimResult{State: executor.OutboxClaimed}, nil
		}
		return executor.OutboxClaimResult{State: executor.OutboxInProgress}, nil
	case "DONE":
		return executor.OutboxClaimResult{State: executor.OutboxCompleted}, nil
	case "PENDING":
		return executor.OutboxClaimResult{State: executor.OutboxPending}, nil
	default:
		// Unknown and FAILED historical states are intentionally treated as
		// in-progress/ambiguous. Automatic retries would weaken the effect
		// boundary precisely when durable evidence is incomplete.
		return executor.OutboxClaimResult{State: executor.OutboxInProgress}, nil
	}
}

func (s *PostgresEffectOutboxStore) validateAndMarshal(effect *contracts.Effect, intent *contracts.AuthorizedExecutionIntent) ([]byte, []byte, error) {
	if s == nil || s.verifier == nil {
		return nil, nil, fmt.Errorf("fail-closed: intent signature verifier unavailable")
	}
	// 1. Verify an executable v2 intent signature at this durable boundary.
	// Legacy v1 signatures remain audit-verifiable but cannot schedule effects.
	if err := crypto.RequireExecutableIntentSignature(intent); err != nil {
		return nil, nil, fmt.Errorf("fail-closed: %w", err)
	}
	valid, err := s.verifier.VerifyIntent(intent)
	if err != nil {
		return nil, nil, fmt.Errorf("fail-closed: error verifying intent: %w", err)
	}
	if !valid {
		return nil, nil, fmt.Errorf("fail-closed: invalid intent signature")
	}
	// Recompute the effect digest here rather than trusting a prior executor
	// check. This closes the persistence boundary against an effect/intention
	// substitution between validation and scheduling.
	effectDigest, err := effectdigest.Canonical(effect)
	if err != nil {
		return nil, nil, fmt.Errorf("fail-closed: canonical effect digest: %w", err)
	}
	if effectDigest != intent.EffectDigestHash {
		return nil, nil, fmt.Errorf("fail-closed: effect digest mismatch (intent=%s, scheduled=%s)", intent.EffectDigestHash, effectDigest)
	}

	effectJSON, err := json.Marshal(effect)
	if err != nil {
		return nil, nil, err
	}
	intentJSON, err := json.Marshal(intent)
	if err != nil {
		return nil, nil, err
	}
	return effectJSON, intentJSON, nil
}

func newClaimToken() (string, error) {
	var raw [16]byte
	if _, err := cryptorand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate outbox claim token: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func (s *PostgresEffectOutboxStore) GetPending(ctx context.Context) ([]*executor.OutboxRecord, error) {
	query := `
		SELECT id, effect_json, decision_json, scheduled_at, status
		FROM effect_outbox
		WHERE status = 'PENDING'
		ORDER BY scheduled_at ASC
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	//nolint:prealloc // result count unknown from SQL query
	var results []*executor.OutboxRecord
	for rows.Next() {
		var id, status string
		var effectJSON, decisionJSON []byte
		var scheduledAt time.Time

		if err := rows.Scan(&id, &effectJSON, &decisionJSON, &scheduledAt, &status); err != nil {
			return nil, err
		}

		var effect contracts.Effect
		if err := json.Unmarshal(effectJSON, &effect); err != nil {
			return nil, fmt.Errorf("corrupt effect JSON in outbox record %s: %w", id, err)
		}
		var intent contracts.AuthorizedExecutionIntent
		if err := json.Unmarshal(decisionJSON, &intent); err != nil {
			return nil, fmt.Errorf("corrupt intent JSON in outbox record %s: %w", id, err)
		}

		results = append(results, &executor.OutboxRecord{
			ID:        id,
			Effect:    &effect,
			Intent:    &intent,
			Scheduled: scheduledAt,
			Status:    status,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func (s *PostgresEffectOutboxStore) MarkDone(ctx context.Context, id string) error {
	query := `UPDATE effect_outbox SET status = 'DONE', completed_at = NOW() WHERE id = $1 AND status = 'CLAIMED'`
	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read outbox completion result: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("outbox intent %q is not an active dispatch claim", id)
	}
	return nil
}
