package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// NewIdempotencyStore creates a new in-memory idempotency store.
func NewIdempotencyStore(ttl time.Duration) *MemoryIdempotencyStore {
	s := &MemoryIdempotencyStore{
		entries:  make(map[string]*cachedResponse),
		inflight: make(map[string]chan struct{}),
		ttl:      ttl,
	}
	// Background cleanup of expired entries
	go s.cleanup()
	return s
}

// Acquire attempts to claim exclusive processing rights for a key.
// Returns (cached, true) if a cached response exists, (nil, true) if the caller wins the race,
// or blocks until the first processor finishes and returns its cached response.
func (s *MemoryIdempotencyStore) Acquire(key string) (*cachedResponse, bool) {
	s.mu.Lock()
	// Check cache first
	if cached, exists := s.entries[key]; exists && time.Since(cached.CachedAt) < s.ttl {
		s.mu.Unlock()
		return cached, true
	}

	// Check if another goroutine is already processing this key
	if ch, inflight := s.inflight[key]; inflight {
		s.mu.Unlock()
		// Wait for the first processor to finish
		<-ch
		// Now check the cache for the result
		s.mu.RLock()
		cached, exists := s.entries[key]
		s.mu.RUnlock()
		if exists && time.Since(cached.CachedAt) < s.ttl {
			return cached, true
		}
		return nil, false
	}

	// We win the race — mark as inflight
	ch := make(chan struct{})
	s.inflight[key] = ch
	s.mu.Unlock()
	return nil, false
}

// Release marks a key as no longer inflight and wakes any waiters.
func (s *MemoryIdempotencyStore) Release(key string) {
	s.mu.Lock()
	if ch, ok := s.inflight[key]; ok {
		delete(s.inflight, key)
		close(ch)
	}
	s.mu.Unlock()
}

func (s *MemoryIdempotencyStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for k, v := range s.entries {
			if now.Sub(v.CachedAt) > s.ttl {
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
	}
}

// Check returns a cached response if existing and valid.
func (s *MemoryIdempotencyStore) Check(key string) (*cachedResponse, bool) {
	s.mu.RLock()
	cached, exists := s.entries[key]
	s.mu.RUnlock()

	if exists && time.Since(cached.CachedAt) < s.ttl {
		return cached, true
	}
	return nil, false
}

// Set stores a response.
func (s *MemoryIdempotencyStore) Set(key string, requestHash string, statusCode int, headers http.Header, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = &cachedResponse{
		RequestHash: requestHash,
		StatusCode:  statusCode,
		Headers:     headers,
		Body:        body,
		CachedAt:    time.Now(),
	}
	return nil
}

// responseCapture wraps http.ResponseWriter to capture the response.
type responseCapture struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	return rc.body.Write(b)
}

// IdempotencyMiddleware ensures that mutating requests with an Idempotency-Key
// header are processed exactly once. Duplicate requests receive the cached response.
// When using MemoryIdempotencyStore, concurrent duplicate requests are serialized
// to prevent TOCTOU races.
func IdempotencyMiddleware(store IdempotencyStorer) func(http.Handler) http.Handler {
	// Check if the store supports atomic acquire/release
	type acquirer interface {
		Acquire(key string) (*cachedResponse, bool)
		Release(key string)
	}
	acq, hasAcquire := store.(acquirer)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only apply to mutating methods
			if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
				next.ServeHTTP(w, r)
				return
			}

			rawKey := r.Header.Get("Idempotency-Key")
			if rawKey == "" {
				next.ServeHTTP(w, r)
				return
			}
			key := scopedIdempotencyKey(r, rawKey)
			requestHash, err := idempotencyRequestHash(r)
			if err != nil {
				WriteBadRequest(w, "invalid idempotent request body")
				return
			}

			// Use atomic acquire if available (prevents TOCTOU race)
			if hasAcquire {
				cached, hit := acq.Acquire(key)
				if hit && cached != nil {
					if !idempotencyHashMatches(cached.RequestHash, requestHash) {
						writeIdempotencyMismatch(w)
						return
					}
					replayCached(w, cached)
					return
				}
				defer acq.Release(key)
			} else {
				// Fallback for non-MemoryIdempotencyStore implementations
				cached, exists := store.Check(key)
				if exists {
					if !idempotencyHashMatches(cached.RequestHash, requestHash) {
						writeIdempotencyMismatch(w)
						return
					}
					replayCached(w, cached)
					return
				}
			}

			// Buffer the response until the idempotency store accepts it. A
			// governed route must not report a completed decision response that
			// cannot be replayed safely on a retry.
			capture := &responseCapture{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(capture, r)

			if err := store.Set(key, requestHash, capture.statusCode, w.Header().Clone(), capture.body.Bytes()); err != nil {
				clearResponseHeaders(w.Header())
				WriteInternal(w, fmt.Errorf("persist idempotent response: %w", err))
				return
			}
			writeCaptured(w, capture)
		})
	}
}

func scopedIdempotencyKey(r *http.Request, rawKey string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n", strings.TrimSpace(rawKey), r.Method, r.URL.EscapedPath(), r.Header.Get("X-Helm-Tenant-ID"), r.Header.Get("X-Helm-Principal-ID"), r.Header.Get("X-Helm-Workspace-ID"), r.Header.Get("X-Helm-Session-ID"))
	return hex.EncodeToString(h.Sum(nil))
}

func writeCaptured(w http.ResponseWriter, capture *responseCapture) {
	w.WriteHeader(capture.statusCode)
	_, _ = w.Write(capture.body.Bytes())
}

func clearResponseHeaders(headers http.Header) {
	for key := range headers {
		headers.Del(key)
	}
}

func idempotencyHashMatches(cachedHash string, requestHash string) bool {
	return cachedHash == "" || cachedHash == requestHash
}

func idempotencyRequestHash(r *http.Request) (string, error) {
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return "", err
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\n%s\n%s\n", r.Method, r.URL.EscapedPath(), r.URL.RawQuery)
	_, _ = h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeIdempotencyMismatch(w http.ResponseWriter) {
	WriteError(w, http.StatusConflict, "Idempotency key conflict", "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST")
}

func replayCached(w http.ResponseWriter, cached *cachedResponse) {
	for k, vals := range cached.Headers {
		for _, v := range vals {
			w.Header().Set(k, v)
		}
	}
	w.Header().Set("X-Helm-Idempotency-Replayed", "true")
	w.WriteHeader(cached.StatusCode)
	_, _ = w.Write(cached.Body)
}
