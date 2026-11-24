package api

import (
	"database/sql"
	"time"
)

// PostgresIdempotencyStore retains the connection and TTL of the former API store.
type PostgresIdempotencyStore struct {
	db  *sql.DB
	ttl time.Duration
}
