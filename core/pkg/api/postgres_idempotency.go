package api

import (
	"database/sql"
	"time"
)

// PostgresIdempotencyStore provides durable idempotency enforcement backed by PostgreSQL.
// Replaces the volatile InMemoryIdempotencyStore to survive process restarts.
type PostgresIdempotencyStore struct {
	db  *sql.DB
	ttl time.Duration
}
