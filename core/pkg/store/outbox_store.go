package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/executor"
)

// PostgresEffectOutboxStore implements executor.OutboxStore
type PostgresEffectOutboxStore struct {
	db *sql.DB
}

func NewPostgresEffectOutboxStore(db *sql.DB) *PostgresEffectOutboxStore {
	return &PostgresEffectOutboxStore{db: db}
}

func (s *PostgresEffectOutboxStore) Schedule(ctx context.Context, effect *contracts.Effect, decision *contracts.DecisionRecord) error {
	effectJSON, err := json.Marshal(effect)
	if err != nil {
		return err
	}
	decisionJSON, err := json.Marshal(decision)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO effect_outbox (id, effect_json, decision_json, scheduled_at, status)
		VALUES ($1, $2, $3, $4, 'PENDING')
		ON CONFLICT (id) DO NOTHING
	`
	// Use DecisionID as ID (idempotency key for schedule)
	_, err = s.db.ExecContext(ctx, query, decision.ID, effectJSON, decisionJSON, time.Now())
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
		var decision contracts.DecisionRecord
		if err := json.Unmarshal(decisionJSON, &decision); err != nil {
			return nil, fmt.Errorf("corrupt decision JSON in outbox record %s: %w", id, err)
		}

		results = append(results, &executor.OutboxRecord{
			ID:        id,
			Effect:    &effect,
			Decision:  &decision,
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
