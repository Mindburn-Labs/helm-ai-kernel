package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimitMiddleware(t *testing.T) {
	// Setup limiter: 1 req/sec, burst 2
	limiter := NewGlobalRateLimiter(1, 2)
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ts := httptest.NewServer(handler)
	defer ts.Close()

	client := ts.Client()

	// Bursts: 2 allowed immediately
	for i := 0; i < 2; i++ {
		resp, err := client.Get(ts.URL)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Within burst limit")
		assert.NoError(t, resp.Body.Close())
	}

	// 3rd request should fail (burst checks happen instantly so tokens consumed)
	// Or maybe slightly delayed? rate.Limiter creates tokens over time.
	// With Limit 1, it takes 1 sec to get token.
	// So 3rd request immediately after should fail.
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("Request 3 failed: %v", err)
	}
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "Exceeded burst")
	assert.NoError(t, resp.Body.Close())

	// Wait 1.1s for token refill
	time.Sleep(1100 * time.Millisecond)

	// 4th request should succeed
	resp, err = client.Get(ts.URL)
	if err != nil {
		t.Fatalf("Request 4 failed: %v", err)
	}
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Refilled token")
	assert.NoError(t, resp.Body.Close())
}

func TestWithContextRateLimit_Passthrough(t *testing.T) {
	handler := WithContextRateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), 10)

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimitMiddleware_EndpointReason(t *testing.T) {
	limiter := NewGlobalRateLimiter(100, 100).WithEndpointLimits(func(*http.Request) string {
		return "kernel"
	}, map[string]RateLimitProfile{"kernel": {RPS: 1, Burst: 1}})
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evaluate", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "ENDPOINT_RATE_LIMIT_EXCEEDED", rec.Header().Get("X-Helm-Limiter-Reason"))
}

func TestRateLimitMiddleware_ActorResourceReason(t *testing.T) {
	limiter := NewGlobalRateLimiter(100, 100).WithActorLimit(RateLimitProfile{RPS: 1, Burst: 1})
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", nil)
	req.Header.Set("X-Helm-Tenant-ID", "tenant")
	req.Header.Set("X-Helm-Principal-ID", "principal")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "ACTOR_RESOURCE_RATE_LIMIT_EXCEEDED", rec.Header().Get("X-Helm-Limiter-Reason"))
}

func TestRateLimitMiddleware_ConcurrencyReason(t *testing.T) {
	limiter := NewGlobalRateLimiter(100, 100).WithConcurrencyLimit(1)
	entered := make(chan struct{})
	releaseHandler := make(chan struct{})
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-releaseHandler
		w.WriteHeader(http.StatusOK)
	}))

	go handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	<-entered
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	close(releaseHandler)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "CONCURRENCY_LIMIT_EXCEEDED", rec.Header().Get("X-Helm-Limiter-Reason"))
}

func TestRateLimitMiddleware_LowPriorityShedReason(t *testing.T) {
	limiter := NewGlobalRateLimiter(100, 100).WithLowPriorityLoadShed(1)
	entered := make(chan struct{})
	releaseHandler := make(chan struct{})
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-releaseHandler
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-Helm-Priority", "low")
	go handler.ServeHTTP(httptest.NewRecorder(), req1)
	<-entered

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Helm-Priority", "low")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req2)
	close(releaseHandler)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "LOW_PRIORITY_LOAD_SHED", rec.Header().Get("X-Helm-Limiter-Reason"))
}
