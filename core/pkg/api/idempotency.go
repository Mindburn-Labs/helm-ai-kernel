package api

import (
	"net/http"
	"sync"
	"time"
)

// cachedResponse stores a previously-seen response for idempotent replay.
type cachedResponse struct {
	RequestHash string
	StatusCode  int
	Headers     http.Header
	Body        []byte
	CachedAt    time.Time
}

// IdempotencyStorer defines the interface for idempotency backends.
type IdempotencyStorer interface {
	Check(key string) (*cachedResponse, bool)
	Set(key string, requestHash string, statusCode int, headers http.Header, body []byte) error
}

// MemoryIdempotencyStore holds cached responses keyed by idempotency key (in-memory).
type MemoryIdempotencyStore struct {
	mu      sync.RWMutex
	entries map[string]*cachedResponse
	// inflight tracks keys currently being processed to prevent TOCTOU races.
	inflight map[string]chan struct{}
	ttl      time.Duration
}
