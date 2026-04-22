package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// EventStore persists trust events in an append-only table.
type EventStore interface {
	// Append persists a new trust event. Returns error if lamport ordering is violated.
	Append(ctx context.Context, event *TrustEvent) error

	// GetAll retrieves all events in lamport order.
	GetAll(ctx context.Context) ([]*TrustEvent, error)

	// GetSince retrieves events with lamport > afterLamport, in order.
	GetSince(ctx context.Context, afterLamport uint64) ([]*TrustEvent, error)

	// GetUpTo retrieves events with lamport <= upToLamport, in order.
	GetUpTo(ctx context.Context, upToLamport uint64) ([]*TrustEvent, error)

	// GetBySubject retrieves events for a specific subject.
	GetBySubject(ctx context.Context, subjectID string) ([]*TrustEvent, error)

	// LatestLamport returns the highest lamport value in the store.
	LatestLamport(ctx context.Context) (uint64, error)
}

// PostgresEventStore implements EventStore using an append-only Postgres table.
type PostgresEventStore struct {
	db *sql.DB
}

// NewPostgresEventStore creates a new Postgres-backed event store.
func NewPostgresEventStore(db *sql.DB) *PostgresEventStore {
	return &PostgresEventStore{db: db}
}

// EnsureTable creates the trust_events table if it doesn't exist.
func (s *PostgresEventStore) EnsureTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS trust_events (
			id           TEXT PRIMARY KEY,
			lamport      BIGINT NOT NULL,
			event_type   TEXT NOT NULL,
			subject_id   TEXT NOT NULL,
			subject_type TEXT NOT NULL,
			payload      JSONB NOT NULL,
			hash         TEXT NOT NULL,
			prev_hash    TEXT NOT NULL DEFAULT '',
			author_kid   TEXT NOT NULL DEFAULT '',
			author_sig   TEXT NOT NULL DEFAULT '',
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

			CONSTRAINT trust_events_lamport_unique UNIQUE (lamport)
		);

		CREATE INDEX IF NOT EXISTS idx_trust_events_lamport ON trust_events (lamport);
		CREATE INDEX IF NOT EXISTS idx_trust_events_subject ON trust_events (subject_id);
		CREATE INDEX IF NOT EXISTS idx_trust_events_type ON trust_events (event_type);
	`
	_, err := s.db.ExecContext(ctx, query)
	return err
}

func (s *PostgresEventStore) Append(ctx context.Context, event *TrustEvent) error {
	query := `
		INSERT INTO trust_events (id, lamport, event_type, subject_id, subject_type, payload, hash, prev_hash, author_kid, author_sig, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := s.db.ExecContext(ctx, query,
		event.ID,
		event.Lamport,
		event.EventType,
		event.SubjectID,
		event.SubjectType,
		event.Payload,
		event.Hash,
		event.PrevHash,
		event.AuthorKID,
		event.AuthorSig,
		event.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("append trust event: %w", err)
	}
	return nil
}

func (s *PostgresEventStore) GetAll(ctx context.Context) ([]*TrustEvent, error) {
	return s.queryEvents(ctx, "SELECT id, lamport, event_type, subject_id, subject_type, payload, hash, prev_hash, author_kid, author_sig, created_at FROM trust_events ORDER BY lamport ASC")
}

func (s *PostgresEventStore) GetSince(ctx context.Context, afterLamport uint64) ([]*TrustEvent, error) {
	return s.queryEvents(ctx,
		"SELECT id, lamport, event_type, subject_id, subject_type, payload, hash, prev_hash, author_kid, author_sig, created_at FROM trust_events WHERE lamport > $1 ORDER BY lamport ASC",
		afterLamport,
	)
}

func (s *PostgresEventStore) GetUpTo(ctx context.Context, upToLamport uint64) ([]*TrustEvent, error) {
	return s.queryEvents(ctx,
		"SELECT id, lamport, event_type, subject_id, subject_type, payload, hash, prev_hash, author_kid, author_sig, created_at FROM trust_events WHERE lamport <= $1 ORDER BY lamport ASC",
		upToLamport,
	)
}

func (s *PostgresEventStore) GetBySubject(ctx context.Context, subjectID string) ([]*TrustEvent, error) {
	return s.queryEvents(ctx,
		"SELECT id, lamport, event_type, subject_id, subject_type, payload, hash, prev_hash, author_kid, author_sig, created_at FROM trust_events WHERE subject_id = $1 ORDER BY lamport ASC",
		subjectID,
	)
}

func (s *PostgresEventStore) LatestLamport(ctx context.Context) (uint64, error) {
	var lamport sql.NullInt64
	err := s.db.QueryRowContext(ctx, "SELECT MAX(lamport) FROM trust_events").Scan(&lamport)
	if err != nil {
		return 0, fmt.Errorf("latest lamport: %w", err)
	}
	if !lamport.Valid {
		return 0, nil
	}
	return uint64(lamport.Int64), nil
}

func (s *PostgresEventStore) queryEvents(ctx context.Context, query string, args ...interface{}) ([]*TrustEvent, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query trust events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []*TrustEvent
	for rows.Next() {
		e := &TrustEvent{}
		var payload []byte
		err := rows.Scan(
			&e.ID, &e.Lamport, &e.EventType,
			&e.SubjectID, &e.SubjectType,
			&payload,
			&e.Hash, &e.PrevHash,
			&e.AuthorKID, &e.AuthorSig,
			&e.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan trust event: %w", err)
		}
		e.Payload = json.RawMessage(payload)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return events, nil
}

// ── Registry Service ─────────────────────────────────────────

// Registry is the top-level trust registry service.
// It combines the event store with the state reducer and provides querying.
type Registry struct {
	store EventStore
	state *TrustState
	clock func() time.Time
}

// NewRegistry creates a new trust registry.
func NewRegistry(store EventStore) *Registry {
	return &Registry{
		store: store,
		state: NewTrustState(),
		clock: time.Now,
	}
}

// Initialize loads all events from the store and rebuilds state.
func (r *Registry) Initialize(ctx context.Context) error {
	events, err := r.store.GetAll(ctx)
	if err != nil {
		return fmt.Errorf("load trust events: %w", err)
	}
	state := NewTrustState()
	if err := state.Reduce(events); err != nil {
		return fmt.Errorf("reduce trust events: %w", err)
	}
	r.state = state
	return nil
}

// AppendEvent validates, hashes, and appends a new trust event.
func (r *Registry) AppendEvent(ctx context.Context, event *TrustEvent) error {
	// Set lamport
	latest, err := r.store.LatestLamport(ctx)
	if err != nil {
		return fmt.Errorf("get latest lamport: %w", err)
	}
	event.Lamport = latest + 1
	event.CreatedAt = r.clock().UTC()

	// Compute hash chain
	if latest > 0 {
		events, err := r.store.GetUpTo(ctx, latest)
		if err != nil {
			return fmt.Errorf("get previous event: %w", err)
		}
		if len(events) > 0 {
			event.PrevHash = events[len(events)-1].Hash
		}
	}

	hash, err := event.ComputeHash()
	if err != nil {
		return fmt.Errorf("compute event hash: %w", err)
	}
	event.Hash = hash

	// Apply to in-memory state first to validate
	if err := r.state.Apply(event); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}

	// Persist
	if err := r.store.Append(ctx, event); err != nil {
		return fmt.Errorf("persist event: %w", err)
	}

	return nil
}

// State returns the current trust state.
func (r *Registry) State() *TrustState {
	return r.state
}

// CurrentLamport returns the current lamport height.
func (r *Registry) CurrentLamport() uint64 {
	return r.state.Lamport
}

// ListEvents returns events since a given lamport height.
func (r *Registry) ListEvents(ctx context.Context, sinceLamport uint64) ([]*TrustEvent, error) {
	if sinceLamport == 0 {
		return r.store.GetAll(ctx)
	}
	return r.store.GetSince(ctx, sinceLamport)
}

// ListEventsBySubject returns all events for a given subject.
func (r *Registry) ListEventsBySubject(ctx context.Context, subjectID string) ([]*TrustEvent, error) {
	return r.store.GetBySubject(ctx, subjectID)
}

// ListEventsUpTo returns events up to a given lamport height (for historical snapshots).
func (r *Registry) ListEventsUpTo(ctx context.Context, upToLamport uint64) ([]*TrustEvent, error) {
	return r.store.GetUpTo(ctx, upToLamport)
}
