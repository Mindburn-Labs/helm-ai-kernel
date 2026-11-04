package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func TestWriteBadRequest(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteBadRequest(rr, "missing field")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
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

// ── IdempotencyMiddleware ───────────────────────────────────

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
