package ledger

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SQLLedger implements Ledger using database/sql.
// It supports both Postgres and SQLite via standard drivers.
type SQLLedger struct {
	db *sql.DB
}

func NewSQLLedger(db *sql.DB) *SQLLedger {
	return &SQLLedger{db: db}
}

const schema = `
CREATE TABLE IF NOT EXISTS obligations (
	id TEXT PRIMARY KEY,
	idempotency_key TEXT UNIQUE,
	intent TEXT,
	state TEXT,
	created_at TIMESTAMP,
	updated_at TIMESTAMP,
	leased_by TEXT,
	leased_until TIMESTAMP,
	plan_attempt_id TEXT
);
`

func (s *SQLLedger) Init(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

func (s *SQLLedger) Create(ctx context.Context, obl Obligation) error {
	query := `
		INSERT INTO obligations (id, idempotency_key, intent, state, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	// Handle idempotent check via unique constraint
	_, err := s.db.ExecContext(ctx, query,
		obl.ID, obl.IdempotencyKey, obl.Intent, obl.State, obl.CreatedAt, obl.UpdatedAt,
	)
	return err
}

func (s *SQLLedger) Get(ctx context.Context, id string) (Obligation, error) {
	query := `SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations WHERE id = $1`
	row := s.db.QueryRowContext(ctx, query, id)

	var obl Obligation
	err := row.Scan(&obl.ID, &obl.IdempotencyKey, &obl.Intent, &obl.State, &obl.CreatedAt, &obl.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Obligation{}, ErrNotFound
		}
		return Obligation{}, err
	}
	return obl, nil
}

func (s *SQLLedger) AcquireLease(ctx context.Context, id, workerID string, duration time.Duration) (Obligation, error) {
	// Optimistic locking logic
	// In Postgres: UPDATE ... RETURNING ... WHERE leased_until < NOW() OR leased_by = workerID

	now := time.Now()
	leasedUntil := now.Add(duration)

	query := `
		UPDATE obligations 
		SET leased_by = $1, leased_until = $2, updated_at = $3
		WHERE id = $4 AND (leased_until < $5 OR leased_by = $1 OR leased_until IS NULL)
	`
	res, err := s.db.ExecContext(ctx, query, workerID, leasedUntil, now, id, now)
	if err != nil {
		return Obligation{}, err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return Obligation{}, fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return Obligation{}, errors.New("locked by another worker")
	}

	return s.Get(ctx, id)
}

func (s *SQLLedger) UpdateState(ctx context.Context, id string, newState State, details map[string]any) error {
	query := `UPDATE obligations SET state = $1, updated_at = $2 WHERE id = $3`
	_, err := s.db.ExecContext(ctx, query, newState, time.Now(), id)
	return err
}

func (s *SQLLedger) ListPending(ctx context.Context) ([]Obligation, error) {
	query := `SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations WHERE state = 'PENDING'`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make([]Obligation, 0)
	for rows.Next() {
		var obl Obligation
		if err := rows.Scan(&obl.ID, &obl.IdempotencyKey, &obl.Intent, &obl.State, &obl.CreatedAt, &obl.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, obl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *SQLLedger) ListAll(ctx context.Context) ([]Obligation, error) {
	query := `SELECT id, idempotency_key, intent, state, created_at, updated_at FROM obligations`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make([]Obligation, 0)
	for rows.Next() {
		var obl Obligation
		if err := rows.Scan(&obl.ID, &obl.IdempotencyKey, &obl.Intent, &obl.State, &obl.CreatedAt, &obl.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, obl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
