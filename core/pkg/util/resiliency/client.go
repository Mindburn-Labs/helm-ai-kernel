package resiliency

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// EnhancedClient wraps http.Client with resilience patterns:
// - Exponential Backoff & Jitter
// - Circuit Breaking
// - Distributed Tracing Injection
type EnhancedClient struct {
	client     *http.Client
	maxRetries int
	breaker    *CircuitBreaker
}

func NewEnhancedClient() *EnhancedClient {
	return &EnhancedClient{
		client:     &http.Client{Timeout: 30 * time.Second},
		maxRetries: 3,
		breaker:    NewCircuitBreaker("default", 5, 10*time.Second),
	}
}

// Do executes an HTTP request with resiliency patterns.
func (c *EnhancedClient) Do(req *http.Request) (*http.Response, error) {
	// 1. Trace Injection (W3C Trace Context)
	// In production, this would grab the span from ctx.
	// Here we stick to a simulated trace ID for observability.
	var traceBytes [16]byte
	traceID := ""
	if _, err := rand.Read(traceBytes[:]); err == nil {
		traceID = hex.EncodeToString(traceBytes[:])
	} else {
		// Best-effort fallback if the system RNG fails.
		traceID = fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	req.Header.Set("traceparent", fmt.Sprintf("00-%s-0000000000000001-01", traceID))

	// 2. Circuit Breaker Check
	if !c.breaker.Allow() {
		return nil, fmt.Errorf("circuit breaker open for %s", c.breaker.name)
	}

	var resp *http.Response
	var err error

	// 3. Retry Loop with Exponential Backoff + Jitter
	for i := 0; i <= c.maxRetries; i++ {
		resp, err = c.client.Do(req)

		// Success
		if err == nil && resp.StatusCode < 500 {
			c.breaker.Success()
			return resp, nil
		}

		// Failure - Check if we should retry
		if i == c.maxRetries {
			break
		}

		// Calculate backoff: base * 2^i + jitter
		backoff := time.Duration(math.Pow(2, float64(i))) * 100 * time.Millisecond
		jitter := time.Duration(0)
		if n, err := rand.Int(rand.Reader, big.NewInt(50)); err == nil {
			jitter = time.Duration(n.Int64()) * time.Millisecond
		}
		time.Sleep(backoff + jitter)
	}

	// 4. Record Failure
	c.breaker.Failure()
	return resp, err
}

// CircuitBreaker implements a simple state machine for failure detection.
type CircuitBreaker struct {
	mu           sync.Mutex
	name         string
	failureCount int
	threshold    int
	lastFailure  time.Time
	resetTimeout time.Duration
	state        string // "CLOSED", "OPEN", "HALF_OPEN"
}

func NewCircuitBreaker(name string, threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:         name,
		threshold:    threshold,
		resetTimeout: timeout,
		state:        "CLOSED",
	}
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == "OPEN" {
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.state = "HALF_OPEN"
			return true
		}
		return false
	}
	return true
}

func (cb *CircuitBreaker) Success() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state == "HALF_OPEN" {
		cb.state = "CLOSED"
		cb.failureCount = 0
	}
	cb.failureCount = 0 // basic reset on success
}

func (cb *CircuitBreaker) Failure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failureCount++
	cb.lastFailure = time.Now()
	if cb.failureCount >= cb.threshold {
		cb.state = "OPEN"
	}
}
