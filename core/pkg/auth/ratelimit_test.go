package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel"
)

func TestRateLimitMiddleware_UnderLimit(t *testing.T) {
	store := kernel.NewInMemoryLimiterStore()
	policy := kernel.BackpressurePolicy{RPM: 60, Burst: 10}
	middleware := auth.RateLimitMiddleware(store, policy)

	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler should be called when under rate limit")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRateLimitMiddleware_OverLimit(t *testing.T) {
	store := kernel.NewInMemoryLimiterStore()
	// Very strict: 1 RPM, burst of 1
	policy := kernel.BackpressurePolicy{RPM: 1, Burst: 1}
	middleware := auth.RateLimitMiddleware(store, policy)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request: should pass
	req1 := httptest.NewRequest("GET", "/api/v1/test", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", w1.Code)
	}

	// Second request: should be rate limited
	req2 := httptest.NewRequest("GET", "/api/v1/test", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", w2.Code)
	}
	if ra := w2.Header().Get("Retry-After"); ra == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}
