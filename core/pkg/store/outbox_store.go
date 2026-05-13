package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
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

func (s *PostgresEffectOutboxStore) Schedule(ctx context.Context, effect *contracts.Effect, intent *contracts.AuthorizedExecutionIntent) error {
	// 1. Verify intent signature for fail-closed boundary
	valid, err := s.verifier.VerifyIntent(intent)
	if err != nil {
		return fmt.Errorf("fail-closed: error verifying intent: %w", err)
	}
	if !valid {
		return fmt.Errorf("fail-closed: invalid intent signature")
	}

	effectJSON, err := json.Marshal(effect)
	if err != nil {
		return err
	}
	intentJSON, err := json.Marshal(intent)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO effect_outbox (id, effect_json, decision_json, scheduled_at, status)
		VALUES ($1, $2, $3, $4, 'PENDING')
		ON CONFLICT (id) DO NOTHING
	`
	// Use intent.ID as ID (idempotency key for schedule)
	_, err = s.db.ExecContext(ctx, query, intent.ID, effectJSON, intentJSON, time.Now())
	if err != nil {
		return fmt.Errorf("failed to schedule effect: %w", err)
	}
	return nil
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
	query := `UPDATE effect_outbox SET status = 'DONE' WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}
