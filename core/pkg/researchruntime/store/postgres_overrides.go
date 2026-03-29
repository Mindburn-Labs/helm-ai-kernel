package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// PostgresOverrideStore implements OverrideStore against research_overrides.
type PostgresOverrideStore struct {
	db *sql.DB
}

// NewPostgresOverrideStore returns a new PostgresOverrideStore.
func NewPostgresOverrideStore(db *sql.DB) *PostgresOverrideStore {
	return &PostgresOverrideStore{db: db}
}

// Save inserts an Override row.
// Maps Override fields to schema columns:
//
//	ID           → id
//	MissionID    → mission_id
//	ArtifactID   → artifact_id
//	ReasonCodes  → reason_codes (JSONB)
//	OperatorID   → operator_id
//	Decision     → decision  (defaults to 'pending')
//	Notes        → notes
func (s *PostgresOverrideStore) Save(ctx context.Context, o Override) error {
	reasonJSON, err := json.Marshal(o.ReasonCodes)
	if err != nil {
		return err
	}
	decision := o.Decision
	if decision == "" {
		decision = "pending"
	}
	const q = `
		INSERT INTO research_overrides
			(id, mission_id, artifact_id, reason_codes,
			 operator_id, decision, notes, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`
	now := time.Now().UTC()
	if !o.CreatedAt.IsZero() {
		now = o.CreatedAt.UTC()
	}
	_, err = s.db.ExecContext(ctx, q,
		o.ID, o.MissionID, nilString(o.ArtifactID), reasonJSON,
		nilString(o.OperatorID), decision, nilString(o.Notes), now,
	)
	return err
}

// Get retrieves an Override by id.
func (s *PostgresOverrideStore) Get(ctx context.Context, id string) (*Override, error) {
	const q = `
		SELECT id, mission_id, artifact_id, reason_codes,
		       operator_id, decision, notes, created_at
		FROM research_overrides
		WHERE id = $1
	`
	row := s.db.QueryRowContext(ctx, q, id)
	o, err := scanOverride(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return o, nil
}

// ListPending returns all overrides with decision = 'pending'.
func (s *PostgresOverrideStore) ListPending(ctx context.Context) ([]Override, error) {
	const q = `
		SELECT id, mission_id, artifact_id, reason_codes,
		       operator_id, decision, notes, created_at
		FROM research_overrides
		WHERE decision = 'pending'
		ORDER BY created_at ASC
	`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make([]Override, 0)
	for rows.Next() {
		o, err := scanOverride(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// Resolve updates the decision, operator_id, and notes on the override.
func (s *PostgresOverrideStore) Resolve(ctx context.Context, id, decision, operatorID, notes string) error {
	const q = `
		UPDATE research_overrides
		SET decision = $1, operator_id = $2, notes = $3
		WHERE id = $4
	`
	_, err := s.db.ExecContext(ctx, q, decision, nilString(operatorID), nilString(notes), id)
	return err
}

// --- helpers ---

func scanOverride(s scanner) (*Override, error) {
	var (
		o           Override
		artifactID  sql.NullString
		reasonJSON  []byte
		operatorID  sql.NullString
		notes       sql.NullString
	)
	err := s.Scan(
		&o.ID, &o.MissionID, &artifactID, &reasonJSON,
		&operatorID, &o.Decision, &notes, &o.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	o.ArtifactID = artifactID.String
	o.OperatorID = operatorID.String
	o.Notes = notes.String
	if len(reasonJSON) > 0 {
		if err := json.Unmarshal(reasonJSON, &o.ReasonCodes); err != nil {
			return nil, err
		}
	}
	return &o, nil
}
