package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// PostgresDraftStore implements DraftStore against research_draft_manifests.
type PostgresDraftStore struct {
	db *sql.DB
}

// NewPostgresDraftStore returns a new PostgresDraftStore.
func NewPostgresDraftStore(db *sql.DB) *PostgresDraftStore {
	return &PostgresDraftStore{db: db}
}

// Save inserts a DraftManifest row.
// Maps DraftManifest fields to schema columns:
//
//	DraftID          → id
//	MissionID        → mission_id
//	ArtifactHashes   → source_refs (JSONB)  — stores the full artifact hash map
//
// state defaults to 'draft' via the DB default.
func (s *PostgresDraftStore) Save(ctx context.Context, d researchruntime.DraftManifest) error {
	sourceRefsJSON, err := json.Marshal(d.ArtifactHashes)
	if err != nil {
		return err
	}
	const q = `
		INSERT INTO research_draft_manifests
			(id, mission_id, source_refs, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$4)
	`
	now := time.Now().UTC()
	if !d.CreatedAt.IsZero() {
		now = d.CreatedAt.UTC()
	}
	_, err = s.db.ExecContext(ctx, q,
		d.DraftID, d.MissionID, sourceRefsJSON, now,
	)
	return err
}

// Get retrieves a DraftManifest by id.
func (s *PostgresDraftStore) Get(ctx context.Context, id string) (*researchruntime.DraftManifest, error) {
	const q = `
		SELECT id, mission_id, source_refs, model_manifest_refs, created_at
		FROM research_draft_manifests
		WHERE id = $1
	`
	row := s.db.QueryRowContext(ctx, q, id)
	d, err := scanDraftManifest(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return d, nil
}

// ListByMission returns all draft manifests for a mission.
func (s *PostgresDraftStore) ListByMission(ctx context.Context, missionID string) ([]researchruntime.DraftManifest, error) {
	const q = `
		SELECT id, mission_id, source_refs, model_manifest_refs, created_at
		FROM research_draft_manifests
		WHERE mission_id = $1
		ORDER BY created_at ASC
	`
	rows, err := s.db.QueryContext(ctx, q, missionID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make([]researchruntime.DraftManifest, 0)
	for rows.Next() {
		d, err := scanDraftManifest(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateState updates the state and updated_at columns.
func (s *PostgresDraftStore) UpdateState(ctx context.Context, id string, state string) error {
	const q = `UPDATE research_draft_manifests SET state = $1, updated_at = $2 WHERE id = $3`
	_, err := s.db.ExecContext(ctx, q, state, time.Now().UTC(), id)
	return err
}

// --- helpers ---

func scanDraftManifest(s scanner) (*researchruntime.DraftManifest, error) {
	var (
		d                   researchruntime.DraftManifest
		sourceRefsJSON      []byte
		modelManifestJSON   []byte
	)
	err := s.Scan(
		&d.DraftID, &d.MissionID,
		&sourceRefsJSON, &modelManifestJSON,
		&d.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(sourceRefsJSON) > 0 {
		if err := json.Unmarshal(sourceRefsJSON, &d.ArtifactHashes); err != nil {
			return nil, err
		}
	}
	// model_manifest_refs is advisory metadata; ignore unmarshal errors.
	_ = modelManifestJSON
	return &d, nil
}
