package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// PostgresPublicationStore implements PublicationStore against research_publications.
type PostgresPublicationStore struct {
	db *sql.DB
}

// NewPostgresPublicationStore returns a new PostgresPublicationStore.
func NewPostgresPublicationStore(db *sql.DB) *PostgresPublicationStore {
	return &PostgresPublicationStore{db: db}
}

// Save inserts a PublicationRecord row.
// Maps PublicationRecord fields to schema columns:
//
//	PublicationID     → id
//	MissionID         → mission_id
//	State             → state
//	Title             → title
//	Slug              → slug
//	EvidencePackHash  → evidence_pack_hash
//	PromotionReceipt  → promotion_receipt_hash
//	SupersededBy      → superseded_by
//	PublishedAt       → published_at
func (s *PostgresPublicationStore) Save(ctx context.Context, p researchruntime.PublicationRecord) error {
	const q = `
		INSERT INTO research_publications
			(id, mission_id, state, title, slug,
			 evidence_pack_hash, promotion_receipt_hash,
			 superseded_by, published_at,
			 created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)
	`
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, q,
		p.PublicationID, p.MissionID, string(p.State),
		nilString(p.Title), nilString(p.Slug),
		nilString(p.EvidencePackHash), nilString(p.PromotionReceipt),
		nilString(p.SupersededBy), nullTimePtr(p.PublishedAt),
		now,
	)
	return err
}

// Get retrieves a PublicationRecord by id.
func (s *PostgresPublicationStore) Get(ctx context.Context, id string) (*researchruntime.PublicationRecord, error) {
	const q = `
		SELECT id, mission_id, state, title, slug,
		       evidence_pack_hash, promotion_receipt_hash,
		       superseded_by, published_at
		FROM research_publications
		WHERE id = $1
	`
	row := s.db.QueryRowContext(ctx, q, id)
	p, err := scanPublication(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return p, nil
}

// GetBySlug retrieves a PublicationRecord by slug.
func (s *PostgresPublicationStore) GetBySlug(ctx context.Context, slug string) (*researchruntime.PublicationRecord, error) {
	const q = `
		SELECT id, mission_id, state, title, slug,
		       evidence_pack_hash, promotion_receipt_hash,
		       superseded_by, published_at
		FROM research_publications
		WHERE slug = $1
	`
	row := s.db.QueryRowContext(ctx, q, slug)
	p, err := scanPublication(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return p, nil
}

// List returns all publications ordered by creation time descending.
func (s *PostgresPublicationStore) List(ctx context.Context) ([]researchruntime.PublicationRecord, error) {
	const q = `
		SELECT id, mission_id, state, title, slug,
		       evidence_pack_hash, promotion_receipt_hash,
		       superseded_by, published_at
		FROM research_publications
		ORDER BY created_at DESC
	`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make([]researchruntime.PublicationRecord, 0)
	for rows.Next() {
		p, err := scanPublication(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateState updates the state and updated_at columns.
func (s *PostgresPublicationStore) UpdateState(ctx context.Context, id string, state string) error {
	const q = `UPDATE research_publications SET state = $1, updated_at = $2 WHERE id = $3`
	_, err := s.db.ExecContext(ctx, q, state, time.Now().UTC(), id)
	return err
}

// SetSupersededBy marks oldID as superseded by newID and transitions its state
// to SUPERSEDED in a single UPDATE statement.
func (s *PostgresPublicationStore) SetSupersededBy(ctx context.Context, oldID, newID string) error {
	const q = `
		UPDATE research_publications
		SET superseded_by = $1, state = 'SUPERSEDED', updated_at = $2
		WHERE id = $3
	`
	_, err := s.db.ExecContext(ctx, q, newID, time.Now().UTC(), oldID)
	return err
}

// --- helpers ---

func scanPublication(s scanner) (*researchruntime.PublicationRecord, error) {
	var (
		p                    researchruntime.PublicationRecord
		title                sql.NullString
		slug                 sql.NullString
		evidencePackHash     sql.NullString
		promotionReceiptHash sql.NullString
		supersededBy         sql.NullString
		publishedAt          sql.NullTime
	)
	err := s.Scan(
		&p.PublicationID, &p.MissionID, &p.State,
		&title, &slug,
		&evidencePackHash, &promotionReceiptHash,
		&supersededBy, &publishedAt,
	)
	if err != nil {
		return nil, err
	}
	p.Title = title.String
	p.Slug = slug.String
	p.EvidencePackHash = evidencePackHash.String
	p.PromotionReceipt = promotionReceiptHash.String
	p.SupersededBy = supersededBy.String
	if publishedAt.Valid {
		t := publishedAt.Time
		p.PublishedAt = &t
	}
	return &p, nil
}

// nullTimePtr returns a sql.NullTime from a *time.Time pointer.
func nullTimePtr(t *time.Time) sql.NullTime {
	if t == nil || t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}
