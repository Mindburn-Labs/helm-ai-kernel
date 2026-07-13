package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SQLiteIdempotencyStore retains completed idempotent responses across process
// restarts in the same SQLite database as the local HELM runtime. The embedded
// coordinator serializes duplicate requests inside one process; the durable
// row protects replay after restart.
type SQLiteIdempotencyStore struct {
	db          *sql.DB
	ttl         time.Duration
	coordinator *MemoryIdempotencyStore
}

func NewSQLiteIdempotencyStore(db *sql.DB, ttl time.Duration) *SQLiteIdempotencyStore {
	return &SQLiteIdempotencyStore{
		db:          db,
		ttl:         ttl,
		coordinator: NewIdempotencyStore(ttl),
	}
}

// Init creates the durable response cache. It is deliberately separate from
// construction so the server can fail startup instead of silently accepting
// governed idempotency keys without persistent replay state.
func (s *SQLiteIdempotencyStore) Init(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("sqlite idempotency store requires a database")
	}
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS idempotency_keys (
			key TEXT PRIMARY KEY,
			request_hash TEXT NOT NULL,
			status_code INTEGER NOT NULL,
			headers BLOB NOT NULL,
			body BLOB NOT NULL,
			cached_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_idempotency_cached_at ON idempotency_keys(cached_at);
	`)
	return err
}

func (s *SQLiteIdempotencyStore) Acquire(key string) (*cachedResponse, bool) {
	if cached, ok := s.Check(key); ok {
		return cached, true
	}
	return s.coordinator.Acquire(key)
}

func (s *SQLiteIdempotencyStore) Release(key string) {
	s.coordinator.Release(key)
}

func (s *SQLiteIdempotencyStore) Check(key string) (*cachedResponse, bool) {
	if s == nil || s.db == nil {
		return nil, false
	}
	var (
		requestHash string
		statusCode  int
		headersRaw  []byte
		body        []byte
		cachedAt    time.Time
	)
	err := s.db.QueryRow(`SELECT request_hash, status_code, headers, body, cached_at FROM idempotency_keys WHERE key = ?`, key).
		Scan(&requestHash, &statusCode, &headersRaw, &body, &cachedAt)
	if err != nil {
		return nil, false
	}
	if requestHash == "" || time.Since(cachedAt) > s.ttl {
		_, _ = s.db.Exec(`DELETE FROM idempotency_keys WHERE key = ?`, key)
		return nil, false
	}
	headers := make(http.Header)
	if len(headersRaw) > 0 && json.Unmarshal(headersRaw, &headers) != nil {
		return nil, false
	}
	return &cachedResponse{
		RequestHash: requestHash,
		StatusCode:  statusCode,
		Headers:     headers,
		Body:        body,
		CachedAt:    cachedAt,
	}, true
}

func (s *SQLiteIdempotencyStore) Set(key string, requestHash string, statusCode int, headers http.Header, body []byte) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("sqlite idempotency store requires a database")
	}
	headersRaw, err := json.Marshal(headers)
	if err != nil {
		return fmt.Errorf("marshal idempotency response headers: %w", err)
	}
	if _, err := s.db.Exec(`
		INSERT INTO idempotency_keys (key, request_hash, status_code, headers, body, cached_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET
			request_hash = excluded.request_hash,
			status_code = excluded.status_code,
			headers = excluded.headers,
			body = excluded.body,
			cached_at = excluded.cached_at`, key, requestHash, statusCode, headersRaw, body); err != nil {
		return err
	}
	return s.coordinator.Set(key, requestHash, statusCode, headers, body)
}

func (s *SQLiteIdempotencyStore) Cleanup() {
	if s == nil || s.db == nil {
		return
	}
	_, _ = s.db.Exec(`DELETE FROM idempotency_keys WHERE cached_at < ?`, time.Now().Add(-s.ttl))
}
