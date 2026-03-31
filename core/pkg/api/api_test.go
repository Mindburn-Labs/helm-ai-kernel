package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── ProblemDetail ────────────────────────────────────────────

func TestProblemDetail_Error(t *testing.T) {
	pd := &ProblemDetail{Title: "Not Found", Detail: "resource xyz missing"}
	got := pd.Error()
	if !strings.Contains(got, "Not Found") || !strings.Contains(got, "resource xyz missing") {
		t.Errorf("unexpected error string: %s", got)
	}
}

// ── Error helpers ────────────────────────────────────────────

func TestWriteError(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteError(rr, http.StatusBadRequest, "Bad Request", "invalid JSON")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("expected application/problem+json, got %s", ct)
	}

	var pd ProblemDetail
	if err := json.Unmarshal(rr.Body.Bytes(), &pd); err != nil {
		t.Fatalf("failed to unmarshal problem detail: %v", err)
	}
	if pd.Status != 400 {
		t.Errorf("expected status 400 in body, got %d", pd.Status)
	}
	if pd.Title != "Bad Request" {
		t.Errorf("unexpected title: %s", pd.Title)
	}
}

func TestWriteErrorR(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resource/123", nil)
	WriteErrorR(rr, req, http.StatusNotFound, "Not Found", "resource 123 not found")

	var pd ProblemDetail
	if err := json.Unmarshal(rr.Body.Bytes(), &pd); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if pd.Instance != "/api/v1/resource/123" {
		t.Errorf("expected instance path, got %s", pd.Instance)
	}
}

func TestWriteBadRequest(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteBadRequest(rr, "missing field")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestWriteUnauthorized(t *testing.T) {
	t.Run("with detail", func(t *testing.T) {
		rr := httptest.NewRecorder()
		WriteUnauthorized(rr, "token expired")
		if rr.Code != 401 {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
	t.Run("empty detail uses default", func(t *testing.T) {
		rr := httptest.NewRecorder()
		WriteUnauthorized(rr, "")
		var pd ProblemDetail
		_ = json.Unmarshal(rr.Body.Bytes(), &pd)
		if pd.Detail != "Authentication required" {
			t.Errorf("expected default detail, got %s", pd.Detail)
		}
	})
}

func TestWriteForbidden(t *testing.T) {
	t.Run("with detail", func(t *testing.T) {
		rr := httptest.NewRecorder()
		WriteForbidden(rr, "admin only")
		if rr.Code != 403 {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})
	t.Run("empty detail uses default", func(t *testing.T) {
		rr := httptest.NewRecorder()
		WriteForbidden(rr, "")
		var pd ProblemDetail
		_ = json.Unmarshal(rr.Body.Bytes(), &pd)
		if pd.Detail != "Insufficient permissions" {
			t.Errorf("expected default detail, got %s", pd.Detail)
		}
	})
}

func TestWriteNotFound(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteNotFound(rr, "user not found")
	if rr.Code != 404 {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestWriteMethodNotAllowed(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteMethodNotAllowed(rr)
	if rr.Code != 405 {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestWriteConflict(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteConflict(rr, "duplicate key")
	if rr.Code != 409 {
		t.Errorf("expected 409, got %d", rr.Code)
	}
}

func TestWriteTooManyRequests(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteTooManyRequests(rr, 10)
	if rr.Code != 429 {
		t.Errorf("expected 429, got %d", rr.Code)
	}
	ra := rr.Header().Get("Retry-After")
	if ra != "10" {
		t.Errorf("expected Retry-After: 10, got %s", ra)
	}
}

func TestWriteInternal(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteInternal(rr, http.ErrAbortHandler)
	if rr.Code != 500 {
		t.Errorf("expected 500, got %d", rr.Code)
	}
	var pd ProblemDetail
	_ = json.Unmarshal(rr.Body.Bytes(), &pd)
	// Must NOT leak internal error details
	if strings.Contains(pd.Detail, "abort") {
		t.Errorf("internal error details should not be leaked: %s", pd.Detail)
	}
	if pd.Detail != "An unexpected error occurred. Please try again later." {
		t.Errorf("expected generic message, got: %s", pd.Detail)
	}
}

// ── MemoryIdempotencyStore ──────────────────────────────────

func TestMemoryIdempotencyStore_SetAndCheck(t *testing.T) {
	store := &MemoryIdempotencyStore{
		entries:  make(map[string]*cachedResponse),
		inflight: make(map[string]chan struct{}),
		ttl:      1 * time.Minute,
	}

	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	store.Set("key-1", 200, headers, []byte(`{"ok":true}`))

	cached, exists := store.Check("key-1")
	if !exists {
		t.Fatal("expected cached response to exist")
	}
	if cached.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", cached.StatusCode)
	}
	if string(cached.Body) != `{"ok":true}` {
		t.Errorf("unexpected body: %s", string(cached.Body))
	}
}

func TestMemoryIdempotencyStore_CheckMiss(t *testing.T) {
	store := &MemoryIdempotencyStore{
		entries:  make(map[string]*cachedResponse),
		inflight: make(map[string]chan struct{}),
		ttl:      1 * time.Minute,
	}

	_, exists := store.Check("nonexistent")
	if exists {
		t.Error("expected cache miss for nonexistent key")
	}
}

func TestMemoryIdempotencyStore_TTLExpiry(t *testing.T) {
	store := &MemoryIdempotencyStore{
		entries: make(map[string]*cachedResponse),
		ttl:     1 * time.Millisecond, // Very short TTL
	}

	store.Set("key-expired", 200, nil, []byte("data"))
	time.Sleep(5 * time.Millisecond)

	_, exists := store.Check("key-expired")
	if exists {
		t.Error("expected expired key to be a cache miss")
	}
}

// ── IdempotencyMiddleware ───────────────────────────────────

func TestIdempotencyMiddleware_GET_PassesThrough(t *testing.T) {
	store := &MemoryIdempotencyStore{
		entries:  make(map[string]*cachedResponse),
		inflight: make(map[string]chan struct{}),
		ttl:      1 * time.Minute,
	}

	handler := IdempotencyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Idempotency-Key", "test-key")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestIdempotencyMiddleware_POST_CachesAndReplays(t *testing.T) {
	store := &MemoryIdempotencyStore{
		entries:  make(map[string]*cachedResponse),
		inflight: make(map[string]chan struct{}),
		ttl:      1 * time.Minute,
	}

	callCount := 0
	handler := IdempotencyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"123"}`))
	}))

	// First call
	req1 := httptest.NewRequest(http.MethodPost, "/", nil)
	req1.Header.Set("Idempotency-Key", "create-123")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	if callCount != 1 {
		t.Errorf("expected handler called once, got %d", callCount)
	}

	// Second call with same key — should replay from cache
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.Header.Set("Idempotency-Key", "create-123")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if callCount != 1 {
		t.Errorf("expected handler NOT called again, got %d", callCount)
	}
}

func TestIdempotencyMiddleware_NoKey_PassesThrough(t *testing.T) {
	store := &MemoryIdempotencyStore{
		entries:  make(map[string]*cachedResponse),
		inflight: make(map[string]chan struct{}),
		ttl:      1 * time.Minute,
	}

	called := false
	handler := IdempotencyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	// No Idempotency-Key header
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected handler to be called when no idempotency key")
	}
}

// ── GlobalRateLimiter ───────────────────────────────────────

func TestGlobalRateLimiter_AllowsRequests(t *testing.T) {
	rl := &GlobalRateLimiter{
		visitors: make(map[string]*visitor),
		config:   rateLimitConfig{rps: 10, burst: 10},
	}

	limiter := rl.getVisitor("192.168.1.1")
	if limiter == nil {
		t.Fatal("expected non-nil limiter")
	}

	// Should allow at least one request
	if !limiter.Allow() {
		t.Error("expected request to be allowed")
	}
}

func TestGlobalRateLimiter_Middleware_AllowsWithinLimit(t *testing.T) {
	rl := &GlobalRateLimiter{
		visitors: make(map[string]*visitor),
		config:   rateLimitConfig{rps: 100, burst: 100},
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestGlobalRateLimiter_Middleware_RejectsOverLimit(t *testing.T) {
	rl := &GlobalRateLimiter{
		visitors: make(map[string]*visitor),
		config:   rateLimitConfig{rps: 1, burst: 1},
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request — should pass
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "10.0.0.2:12345"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	// Rapid second request — should be rate limited
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.2:12345"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != 429 {
		t.Errorf("expected 429 rate limit, got %d", rr2.Code)
	}
}

// ── responseCapture ─────────────────────────────────────────

func TestResponseCapture(t *testing.T) {
	rr := httptest.NewRecorder()
	rc := &responseCapture{ResponseWriter: rr, statusCode: http.StatusOK}

	rc.WriteHeader(http.StatusCreated)
	n, err := rc.Write([]byte("hello"))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes written, got %d", n)
	}
	if rc.statusCode != http.StatusCreated {
		t.Errorf("expected captured status 201, got %d", rc.statusCode)
	}
	if rc.body.String() != "hello" {
		t.Errorf("expected captured body 'hello', got %s", rc.body.String())
	}
}
