package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// PostgresTaskStore implements TaskStore against research_tasks.
type PostgresTaskStore struct {
	db *sql.DB
}

// NewPostgresTaskStore returns a new PostgresTaskStore.
func NewPostgresTaskStore(db *sql.DB) *PostgresTaskStore {
	return &PostgresTaskStore{db: db}
}

// Create inserts a new TaskLease row.
// Maps TaskLease fields to schema columns:
//
//	LeaseID    → id
//	MissionID  → mission_id
//	NodeID     → node_id
//	Role       → role
//	Assignee   → (not in schema; stored implicitly via lease_holder on acquisition)
//	RetryCount → attempt
//	DeadlineAt → deadline_at
//
// state defaults to 'pending' via the DB default.
func (s *PostgresTaskStore) Create(ctx context.Context, t researchruntime.TaskLease) error {
	const q = `
		INSERT INTO research_tasks
			(id, mission_id, node_id, role, attempt, deadline_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
	`
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, q,
		t.LeaseID, t.MissionID, t.NodeID, string(t.Role),
		t.RetryCount, nullTime(t.DeadlineAt), now,
	)
	return err
}

// Get retrieves a TaskLease by id.
func (s *PostgresTaskStore) Get(ctx context.Context, id string) (*researchruntime.TaskLease, error) {
	const q = `
		SELECT id, mission_id, node_id, role, attempt,
		       lease_holder, lease_until, deadline_at
		FROM research_tasks
		WHERE id = $1
	`
	row := s.db.QueryRowContext(ctx, q, id)
	t, err := scanTaskLease(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t, nil
}

// UpdateState updates the state and updated_at columns.
func (s *PostgresTaskStore) UpdateState(ctx context.Context, id, state string) error {
	const q = `UPDATE research_tasks SET state = $1, updated_at = $2 WHERE id = $3`
	_, err := s.db.ExecContext(ctx, q, state, time.Now().UTC(), id)
	return err
}

// ListByMission returns all task leases for a given mission.
func (s *PostgresTaskStore) ListByMission(ctx context.Context, missionID string) ([]researchruntime.TaskLease, error) {
	const q = `
		SELECT id, mission_id, node_id, role, attempt,
		       lease_holder, lease_until, deadline_at
		FROM research_tasks
		WHERE mission_id = $1
		ORDER BY created_at ASC
	`
	rows, err := s.db.QueryContext(ctx, q, missionID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make([]researchruntime.TaskLease, 0)
	for rows.Next() {
		t, err := scanTaskLease(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// AcquireLease atomically sets lease_holder and lease_until only when the task
// is currently unleased or the existing lease has expired.
func (s *PostgresTaskStore) AcquireLease(ctx context.Context, id, workerID string, until time.Time) error {
	const q = `
		UPDATE research_tasks
		SET lease_holder = $1, lease_until = $2, updated_at = $3
		WHERE id = $4
		  AND (lease_holder IS NULL OR lease_until < NOW())
	`
	res, err := s.db.ExecContext(ctx, q, workerID, until.UTC(), time.Now().UTC(), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("store: lease already held")
	}
	return nil
}

// ReleaseLease clears the lease_holder and lease_until columns.
func (s *PostgresTaskStore) ReleaseLease(ctx context.Context, id string) error {
	const q = `
		UPDATE research_tasks
		SET lease_holder = NULL, lease_until = NULL, updated_at = $1
		WHERE id = $2
	`
	_, err := s.db.ExecContext(ctx, q, time.Now().UTC(), id)
	return err
}

// --- internal helpers ---

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanTaskLease(s scanner) (*researchruntime.TaskLease, error) {
	var (
		t           researchruntime.TaskLease
		leaseHolder sql.NullString
		leaseUntil  sql.NullTime
		deadlineAt  sql.NullTime
	)
	err := s.Scan(
		&t.LeaseID, &t.MissionID, &t.NodeID, &t.Role, &t.RetryCount,
		&leaseHolder, &leaseUntil, &deadlineAt,
	)
	if err != nil {
		return nil, err
	}
	if leaseHolder.Valid {
		t.Assignee = leaseHolder.String
	}
	if deadlineAt.Valid {
		t.DeadlineAt = deadlineAt.Time
	}
	if leaseUntil.Valid {
		ts := leaseUntil.Time
		t.EscalationAt = &ts
	}
	return &t, nil
}

// nullTime returns a sql.NullTime that is valid iff t is non-zero.
func nullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}
