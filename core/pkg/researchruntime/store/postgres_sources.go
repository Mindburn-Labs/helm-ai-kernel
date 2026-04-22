package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// PostgresSourceStore implements SourceStore against research_source_snapshots.
type PostgresSourceStore struct {
	db *sql.DB
}

// NewPostgresSourceStore returns a new PostgresSourceStore.
func NewPostgresSourceStore(db *sql.DB) *PostgresSourceStore {
	return &PostgresSourceStore{db: db}
}

// Save inserts a SourceSnapshot row.
// Maps SourceSnapshot fields to schema columns:
//
//	SourceID         → id
//	MissionID        → mission_id
//	URL              → url
//	CanonicalURL     → canonical_url
//	Title            → title
//	ContentHash      → content_hash
//	SnapshotHash     → snapshot_hash
//	FreshnessScore   → freshness_score
//	Primary          → is_primary
//	CapturedAt       → captured_at
//	ProvenanceStatus → state
func (s *PostgresSourceStore) Save(ctx context.Context, src researchruntime.SourceSnapshot) error {
	const q = `
		INSERT INTO research_source_snapshots
			(id, mission_id, url, canonical_url, title,
			 content_hash, snapshot_hash,
			 freshness_score, is_primary,
			 state, captured_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	`
	capturedAt := sql.NullTime{}
	if !src.CapturedAt.IsZero() {
		capturedAt = sql.NullTime{Time: src.CapturedAt.UTC(), Valid: true}
	}
	_, err := s.db.ExecContext(ctx, q,
		src.SourceID, src.MissionID,
		src.URL, nilString(src.CanonicalURL), nilString(src.Title),
		nilString(src.ContentHash), nilString(src.SnapshotHash),
		src.FreshnessScore, src.Primary,
		string(src.ProvenanceStatus), capturedAt,
		time.Now().UTC(),
	)
	return err
}

// Get retrieves a SourceSnapshot by id.
func (s *PostgresSourceStore) Get(ctx context.Context, id string) (*researchruntime.SourceSnapshot, error) {
	const q = `
		SELECT id, mission_id, url, canonical_url, title,
		       content_hash, snapshot_hash,
		       freshness_score, is_primary,
		       state, captured_at
		FROM research_source_snapshots
		WHERE id = $1
	`
	row := s.db.QueryRowContext(ctx, q, id)
	src, err := scanSourceSnapshot(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return src, nil
}

// ListByMission returns all source snapshots for a mission.
func (s *PostgresSourceStore) ListByMission(ctx context.Context, missionID string) ([]researchruntime.SourceSnapshot, error) {
	const q = `
		SELECT id, mission_id, url, canonical_url, title,
		       content_hash, snapshot_hash,
		       freshness_score, is_primary,
		       state, captured_at
		FROM research_source_snapshots
		WHERE mission_id = $1
		ORDER BY created_at ASC
	`
	rows, err := s.db.QueryContext(ctx, q, missionID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make([]researchruntime.SourceSnapshot, 0)
	for rows.Next() {
		src, err := scanSourceSnapshot(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *src)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateState updates the state column for the given source.
func (s *PostgresSourceStore) UpdateState(ctx context.Context, id string, state string) error {
	const q = `UPDATE research_source_snapshots SET state = $1 WHERE id = $2`
	_, err := s.db.ExecContext(ctx, q, state, id)
	return err
}

// --- helpers ---

func scanSourceSnapshot(s scanner) (*researchruntime.SourceSnapshot, error) {
	var (
		src          researchruntime.SourceSnapshot
		canonicalURL sql.NullString
		title        sql.NullString
		contentHash  sql.NullString
		snapshotHash sql.NullString
		state        sql.NullString
		capturedAt   sql.NullTime
	)
	err := s.Scan(
		&src.SourceID, &src.MissionID, &src.URL,
		&canonicalURL, &title,
		&contentHash, &snapshotHash,
		&src.FreshnessScore, &src.Primary,
		&state, &capturedAt,
	)
	if err != nil {
		return nil, err
	}
	src.CanonicalURL = canonicalURL.String
	src.Title = title.String
	src.ContentHash = contentHash.String
	src.SnapshotHash = snapshotHash.String
	if state.Valid {
		src.ProvenanceStatus = researchruntime.ProvenanceStatus(state.String)
	}
	if capturedAt.Valid {
		src.CapturedAt = capturedAt.Time
	}
	return &src, nil
}

// nilString returns a sql.NullString that is valid only when s is non-empty.
func nilString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
