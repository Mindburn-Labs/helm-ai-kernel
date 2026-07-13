package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PostgresIdempotencyStore provides durable idempotency enforcement backed by PostgreSQL.
// Replaces the volatile InMemoryIdempotencyStore to survive process restarts.
type PostgresIdempotencyStore struct {
	db          *sql.DB
	ttl         time.Duration
	coordinator *MemoryIdempotencyStore
}

// NewPostgresIdempotencyStore creates a new PostgreSQL-backed idempotency store.
func NewPostgresIdempotencyStore(db *sql.DB, ttl time.Duration) *PostgresIdempotencyStore {
	return &PostgresIdempotencyStore{db: db, ttl: ttl, coordinator: NewIdempotencyStore(ttl)}
}

// Init creates (or upgrades) the durable response cache before any governed
// route accepts an Idempotency-Key. Historic rows without a request hash are
// intentionally discarded on read because their body binding cannot be proven.
func (s *PostgresIdempotencyStore) Init(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres idempotency store requires a database")
	}
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS idempotency_keys (
			key TEXT PRIMARY KEY,
			request_hash TEXT NOT NULL,
			status_code INTEGER NOT NULL,
			headers BYTEA NOT NULL,
			body BYTEA NOT NULL,
			cached_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_idempotency_cached_at ON idempotency_keys(cached_at);
	`)
	return err
}

func (s *PostgresIdempotencyStore) Acquire(key string) (*cachedResponse, bool) {
	if cached, ok := s.Check(key); ok {
		return cached, true
	}
	return s.coordinator.Acquire(key)
}

func (s *PostgresIdempotencyStore) Release(key string) {
	s.coordinator.Release(key)
}

// Check returns a cached response if the idempotency key was seen before and is within TTL.
func (s *PostgresIdempotencyStore) Check(key string) (*cachedResponse, bool) {
	if s == nil || s.db == nil {
		return nil, false
	}
	var requestHash string
	var statusCode int
	var headers []byte
	var body []byte
	var cachedAt time.Time

	err := s.db.QueryRow(
		`SELECT request_hash, status_code, headers, body, cached_at FROM idempotency_keys WHERE key = $1`,
		key,
	).Scan(&requestHash, &statusCode, &headers, &body, &cachedAt)
	if err != nil {
		return nil, false
	}

	// Check TTL
	if requestHash == "" || time.Since(cachedAt) > s.ttl {
		// Expired — delete and return miss
		_, _ = s.db.Exec(`DELETE FROM idempotency_keys WHERE key = $1`, key)
		return nil, false
	}

	hdr := make(http.Header)
	if len(headers) > 0 && json.Unmarshal(headers, &hdr) != nil {
		return nil, false
	}
	if hdr.Get("Content-Type") == "" {
		// Historic rows stored `{}` rather than a serialized header map. They
		// are safe to replay only when they retain a request hash; preserve the
		// prior JSON response default for that migration path.
		hdr.Set("Content-Type", "application/json")
	}

	return &cachedResponse{
		RequestHash: requestHash,
		StatusCode:  statusCode,
		Headers:     hdr,
		Body:        body,
		CachedAt:    cachedAt,
	}, true
}

// Set stores an idempotency key and its response.
// Fail-closed: returns error if persistence fails. Callers must handle this for protected actions.
func (s *PostgresIdempotencyStore) Set(key string, requestHash string, statusCode int, headers http.Header, body []byte) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres idempotency store requires a database")
	}
	headersRaw, err := json.Marshal(headers)
	if err != nil {
		return fmt.Errorf("marshal idempotency response headers: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO idempotency_keys (key, request_hash, status_code, headers, body, cached_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())
		 ON CONFLICT (key) DO UPDATE SET request_hash = $2, status_code = $3, headers = $4, body = $5, cached_at = NOW()`,
		key, requestHash, statusCode, headersRaw, body,
	)
	if err != nil {
		return fmt.Errorf("idempotency: failed to persist key %s: %w", key, err)
	}
	return s.coordinator.Set(key, requestHash, statusCode, headers, body)
}

// Cleanup removes expired idempotency keys older than the TTL.
func (s *PostgresIdempotencyStore) Cleanup() {
	_, _ = s.db.Exec(
		`DELETE FROM idempotency_keys WHERE cached_at < $1`,
		time.Now().Add(-s.ttl),
	)
}
