package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"
)

// PostgresIdempotencyStore provides durable idempotency enforcement backed by PostgreSQL.
// Replaces the volatile InMemoryIdempotencyStore to survive process restarts.
type PostgresIdempotencyStore struct {
	db  *sql.DB
	ttl time.Duration
}

// NewPostgresIdempotencyStore creates a new PostgreSQL-backed idempotency store.
func NewPostgresIdempotencyStore(db *sql.DB, ttl time.Duration) *PostgresIdempotencyStore {
	return &PostgresIdempotencyStore{db: db, ttl: ttl}
}

// Check returns a cached response if the idempotency key was seen before and is within TTL.
func (s *PostgresIdempotencyStore) Check(key string) (*cachedResponse, bool) {
	var statusCode int
	var headers []byte
	var body []byte
	var cachedAt time.Time

	err := s.db.QueryRow(
		`SELECT status_code, headers, body, cached_at FROM idempotency_keys WHERE key = $1`,
		key,
	).Scan(&statusCode, &headers, &body, &cachedAt)
	if err != nil {
		return nil, false
	}

	// Check TTL
	if time.Since(cachedAt) > s.ttl {
		// Expired — delete and return miss
		_, _ = s.db.Exec(`DELETE FROM idempotency_keys WHERE key = $1`, key)
		return nil, false
	}

	// Reconstruct headers
	hdr := make(http.Header)
	// Headers are stored as key:value pairs; for simplicity we store Content-Type only
	hdr.Set("Content-Type", "application/json")

	return &cachedResponse{
		StatusCode: statusCode,
		Headers:    hdr,
		Body:       body,
	}, true
}

// Set stores an idempotency key and its response.
// Fail-closed: returns error if persistence fails. Callers must handle this for protected actions.
func (s *PostgresIdempotencyStore) Set(key string, statusCode int, headers http.Header, body []byte) error {
	_, err := s.db.Exec(
		`INSERT INTO idempotency_keys (key, status_code, headers, body, cached_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (key) DO UPDATE SET status_code = $2, headers = $3, body = $4, cached_at = NOW()`,
		key, statusCode, []byte("{}"), body,
	)
	if err != nil {
		return fmt.Errorf("idempotency: failed to persist key %s: %w", key, err)
	}
	return nil
}

// Cleanup removes expired idempotency keys older than the TTL.
func (s *PostgresIdempotencyStore) Cleanup() {
	_, _ = s.db.Exec(
		`DELETE FROM idempotency_keys WHERE cached_at < $1`,
		time.Now().Add(-s.ttl),
	)
}
