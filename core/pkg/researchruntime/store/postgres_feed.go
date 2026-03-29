package store

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// PostgresFeedStore implements FeedStore against research_feed_events.
type PostgresFeedStore struct {
	db *sql.DB
}

// NewPostgresFeedStore returns a new PostgresFeedStore.
func NewPostgresFeedStore(db *sql.DB) *PostgresFeedStore {
	return &PostgresFeedStore{db: db}
}

// Append inserts a new feed event. A UUID is generated for the id column.
func (s *PostgresFeedStore) Append(ctx context.Context, missionID, actor, action, detail string) error {
	const q = `
		INSERT INTO research_feed_events (id, mission_id, actor, action, detail)
		VALUES ($1,$2,$3,$4,$5)
	`
	_, err := s.db.ExecContext(ctx, q,
		uuid.New().String(), missionID, actor, action, detail,
	)
	return err
}

// Latest returns the most recent feed events across all missions, newest first.
func (s *PostgresFeedStore) Latest(ctx context.Context, limit int) ([]FeedEvent, error) {
	const q = `
		SELECT id, mission_id, actor, action, detail, created_at
		FROM research_feed_events
		ORDER BY created_at DESC
		LIMIT $1
	`
	rows, err := s.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanFeedEvents(rows)
}

// ByMission returns all feed events for a mission, newest first.
func (s *PostgresFeedStore) ByMission(ctx context.Context, missionID string) ([]FeedEvent, error) {
	const q = `
		SELECT id, mission_id, actor, action, detail, created_at
		FROM research_feed_events
		WHERE mission_id = $1
		ORDER BY created_at DESC
	`
	rows, err := s.db.QueryContext(ctx, q, missionID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanFeedEvents(rows)
}

func scanFeedEvents(rows *sql.Rows) ([]FeedEvent, error) {
	result := make([]FeedEvent, 0)
	for rows.Next() {
		var (
			e      FeedEvent
			detail sql.NullString
		)
		if err := rows.Scan(
			&e.ID, &e.MissionID, &e.Actor, &e.Action, &detail, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		e.Detail = detail.String
		result = append(result, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
