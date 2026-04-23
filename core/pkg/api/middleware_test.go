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
