package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// PostgresMissionStore implements MissionStore against research_missions.
type PostgresMissionStore struct {
	db *sql.DB
}

// NewPostgresMissionStore returns a new PostgresMissionStore.
func NewPostgresMissionStore(db *sql.DB) *PostgresMissionStore {
	return &PostgresMissionStore{db: db}
}

// Create inserts a new MissionSpec row.
// Maps MissionSpec fields to schema columns:
//
//	MissionID        → id
//	Class            → type
//	Title            → title
//	Thesis           → objective
//	QuerySeeds[0]    → query_seed   (first seed; remaining are advisory)
//	MaxBudgetTokens  → budget_tokens_max
//	MaxBudgetCents   → budget_cents_max
//	Trigger.Type     → trigger_type
//	Trigger.Schedule → trigger_cron
//
// state defaults to 'created' via the DB default.
func (s *PostgresMissionStore) Create(ctx context.Context, m researchruntime.MissionSpec) error {
	querySeed := ""
	if len(m.QuerySeeds) > 0 {
		querySeed = m.QuerySeeds[0]
	}
	const q = `
		INSERT INTO research_missions
			(id, type, title, objective, query_seed,
			 budget_tokens_max, budget_cents_max,
			 trigger_type, trigger_cron,
			 created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`
	now := time.Now().UTC()
	if !m.CreatedAt.IsZero() {
		now = m.CreatedAt.UTC()
	}
	_, err := s.db.ExecContext(ctx, q,
		m.MissionID, string(m.Class), m.Title, m.Thesis, querySeed,
		m.MaxBudgetTokens, m.MaxBudgetCents,
		string(m.Trigger.Type), m.Trigger.Schedule,
		now, now,
	)
	return err
}

// Get retrieves a MissionSpec by id.
func (s *PostgresMissionStore) Get(ctx context.Context, id string) (*researchruntime.MissionSpec, error) {
	const q = `
		SELECT id, type, title, objective, query_seed,
		       budget_tokens_max, budget_cents_max,
		       trigger_type, trigger_cron, created_at
		FROM research_missions
		WHERE id = $1
	`
	row := s.db.QueryRowContext(ctx, q, id)

	var (
		m             researchruntime.MissionSpec
		querySeed     sql.NullString
		triggerType   sql.NullString
		triggerCron   sql.NullString
		budgetTokens  sql.NullInt64
		budgetCents   sql.NullInt64
	)
	err := row.Scan(
		&m.MissionID, &m.Class, &m.Title, &m.Thesis, &querySeed,
		&budgetTokens, &budgetCents,
		&triggerType, &triggerCron, &m.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if querySeed.Valid {
		m.QuerySeeds = []string{querySeed.String}
	}
	if budgetTokens.Valid {
		m.MaxBudgetTokens = int(budgetTokens.Int64)
	}
	if budgetCents.Valid {
		m.MaxBudgetCents = int(budgetCents.Int64)
	}
	if triggerType.Valid {
		m.Trigger.Type = researchruntime.MissionTriggerType(triggerType.String)
	}
	if triggerCron.Valid {
		m.Trigger.Schedule = triggerCron.String
	}
	return &m, nil
}

// UpdateState updates only the state and updated_at columns.
func (s *PostgresMissionStore) UpdateState(ctx context.Context, id string, state string) error {
	const q = `UPDATE research_missions SET state = $1, updated_at = $2 WHERE id = $3`
	_, err := s.db.ExecContext(ctx, q, state, time.Now().UTC(), id)
	return err
}

// List returns missions with optional state/class filters and a row limit.
func (s *PostgresMissionStore) List(ctx context.Context, f MissionFilter) ([]researchruntime.MissionSpec, error) {
	query := `
		SELECT id, type, title, objective, query_seed,
		       budget_tokens_max, budget_cents_max,
		       trigger_type, trigger_cron, created_at
		FROM research_missions
		WHERE 1=1`
	args := make([]any, 0, 3)
	n := 1

	if f.State != nil {
		query += ` AND state = $` + itoa(n)
		args = append(args, *f.State)
		n++
	}
	if f.Class != nil {
		query += ` AND type = $` + itoa(n)
		args = append(args, *f.Class)
		n++
	}
	query += ` ORDER BY created_at DESC`
	if f.Limit > 0 {
		query += ` LIMIT $` + itoa(n)
		args = append(args, f.Limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make([]researchruntime.MissionSpec, 0)
	for rows.Next() {
		var (
			m            researchruntime.MissionSpec
			querySeed    sql.NullString
			triggerType  sql.NullString
			triggerCron  sql.NullString
			budgetTokens sql.NullInt64
			budgetCents  sql.NullInt64
		)
		if err := rows.Scan(
			&m.MissionID, &m.Class, &m.Title, &m.Thesis, &querySeed,
			&budgetTokens, &budgetCents,
			&triggerType, &triggerCron, &m.CreatedAt,
		); err != nil {
			return nil, err
		}
		if querySeed.Valid {
			m.QuerySeeds = []string{querySeed.String}
		}
		if budgetTokens.Valid {
			m.MaxBudgetTokens = int(budgetTokens.Int64)
		}
		if budgetCents.Valid {
			m.MaxBudgetCents = int(budgetCents.Int64)
		}
		if triggerType.Valid {
			m.Trigger.Type = researchruntime.MissionTriggerType(triggerType.String)
		}
		if triggerCron.Valid {
			m.Trigger.Schedule = triggerCron.String
		}
		result = append(result, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
