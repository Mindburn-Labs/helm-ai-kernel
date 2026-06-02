package resiliency

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEnhancedClientDefaults(t *testing.T) {
	client := NewEnhancedClient()
	if client.client == nil || client.client.Timeout != 30*time.Second {
		t.Fatalf("unexpected http client: %#v", client.client)
	}
	if client.maxRetries != 3 {
		t.Fatalf("maxRetries = %d, want 3", client.maxRetries)
	}
	if client.breaker == nil || client.breaker.name != "default" || client.breaker.threshold != 5 || client.breaker.resetTimeout != 10*time.Second {
		t.Fatalf("unexpected breaker: %#v", client.breaker)
	}
}

func TestDoSuccessInjectsTraceparent(t *testing.T) {
	restore := replaceHooks()
	defer restore()

	readTraceRandom = func(buf []byte) (int, error) {
		for i := range buf {
			buf[i] = byte(i + 1)
		}
		return len(buf), nil
	}

	var traceparent string
	client := NewEnhancedClient()
	client.breaker.failureCount = 3
	client.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		traceparent = req.Header.Get("traceparent")
		return response(http.StatusOK), nil
	})

	resp, err := client.Do(newRequest(t))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if traceparent != "00-0102030405060708090a0b0c0d0e0f10-0000000000000001-01" {
		t.Fatalf("unexpected traceparent %q", traceparent)
	}
	if client.breaker.failureCount != 0 {
		t.Fatalf("expected breaker failure count reset, got %d", client.breaker.failureCount)
	}
}

func TestDoTraceFallbackAndRetry(t *testing.T) {
	restore := replaceHooks()
	defer restore()

	readTraceRandom = func([]byte) (int, error) {
		return 0, errors.New("rng failed")
	}
	now = func() time.Time {
		return time.Unix(0, 123)
	}
	readJitterRandom = func(io.Reader, *big.Int) (*big.Int, error) {
		return big.NewInt(5), nil
	}
	var slept []time.Duration
	sleep = func(d time.Duration) {
		slept = append(slept, d)
	}

	calls := 0
	var traceparent string
	client := NewEnhancedClient()
	client.maxRetries = 1
	client.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		traceparent = req.Header.Get("traceparent")
		if calls == 1 {
			return response(http.StatusInternalServerError), nil
		}
		return response(http.StatusNoContent), nil
	})

	resp, err := client.Do(newRequest(t))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent || calls != 2 {
		t.Fatalf("status/calls = %d/%d", resp.StatusCode, calls)
	}
	if traceparent != "00-0000000000000000000000000000007b-0000000000000001-01" {
		t.Fatalf("unexpected fallback traceparent %q", traceparent)
	}
	if len(slept) != 1 || slept[0] != 105*time.Millisecond {
		t.Fatalf("unexpected sleep durations %v", slept)
	}
}

func TestDoTransportFailureRecordsBreaker(t *testing.T) {
	restore := replaceHooks()
	defer restore()

	readJitterRandom = func(io.Reader, *big.Int) (*big.Int, error) {
		return nil, errors.New("jitter failed")
	}
	sleep = func(time.Duration) {}

	client := NewEnhancedClient()
	client.maxRetries = 1
	client.breaker.threshold = 1
	client.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network failed")
	})

	resp, err := client.Do(newRequest(t))
	if err == nil || !strings.Contains(err.Error(), "network failed") {
		t.Fatalf("expected network error, got resp=%v err=%v", resp, err)
	}
	if client.breaker.state != "OPEN" || client.breaker.failureCount != 1 {
		t.Fatalf("breaker not opened after failure: %#v", client.breaker)
	}
}

func TestDoServerErrorExhaustionRecordsFailure(t *testing.T) {
	restore := replaceHooks()
	defer restore()

	client := NewEnhancedClient()
	client.maxRetries = 0
	client.breaker.threshold = 1
	client.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusBadGateway), nil
	})

	resp, err := client.Do(newRequest(t))
	if err != nil {
		t.Fatalf("Do returned unexpected transport error: %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("unexpected response %#v", resp)
	}
	if client.breaker.state != "OPEN" {
		t.Fatalf("expected breaker open, got %#v", client.breaker)
	}
}

func TestDoCircuitBreakerOpen(t *testing.T) {
	restore := replaceHooks()
	defer restore()

	since = func(time.Time) time.Duration {
		return time.Second
	}

	client := NewEnhancedClient()
	client.breaker.state = "OPEN"
	client.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport should not be called while breaker is open")
		return nil, nil
	})

	resp, err := client.Do(newRequest(t))
	if resp != nil || err == nil || !strings.Contains(err.Error(), "circuit breaker open for default") {
		t.Fatalf("expected open breaker error, got resp=%v err=%v", resp, err)
	}
}

func TestCircuitBreakerStateTransitions(t *testing.T) {
	restore := replaceHooks()
	defer restore()

	cb := NewCircuitBreaker("test", 2, time.Second)
	if !cb.Allow() {
		t.Fatal("closed breaker should allow")
	}
	cb.Failure()
	if cb.state != "CLOSED" || cb.failureCount != 1 {
		t.Fatalf("unexpected first failure state: %#v", cb)
	}
	cb.Failure()
	if cb.state != "OPEN" {
		t.Fatalf("expected open breaker, got %#v", cb)
	}

	since = func(time.Time) time.Duration {
		return 2 * time.Second
	}
	if !cb.Allow() || cb.state != "HALF_OPEN" {
		t.Fatalf("expected half-open allow, got %#v", cb)
	}
	cb.Success()
	if cb.state != "CLOSED" || cb.failureCount != 0 {
		t.Fatalf("expected success reset, got %#v", cb)
	}
}

func TestJitterDelay(t *testing.T) {
	restore := replaceHooks()
	defer restore()

	readJitterRandom = func(io.Reader, *big.Int) (*big.Int, error) {
		return big.NewInt(7), nil
	}
	if got := jitterDelay(); got != 7*time.Millisecond {
		t.Fatalf("jitterDelay = %s", got)
	}

	readJitterRandom = func(io.Reader, *big.Int) (*big.Int, error) {
		return nil, errors.New("rng failed")
	}
	if got := jitterDelay(); got != 0 {
		t.Fatalf("jitterDelay error path = %s", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func response(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
	}
}

func newRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	return req
}

func replaceHooks() func() {
	originalReadTraceRandom := readTraceRandom
	originalReadJitterRandom := readJitterRandom
	originalSleep := sleep
	originalNow := now
	originalSince := since
	readTraceRandom = rand.Read
	readJitterRandom = rand.Int
	sleep = time.Sleep
	now = time.Now
	since = time.Since
	return func() {
		readTraceRandom = originalReadTraceRandom
		readJitterRandom = originalReadJitterRandom
		sleep = originalSleep
		now = originalNow
		since = originalSince
	}
}
