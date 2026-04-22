package kernel

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BackpressurePolicy defines limits.
type BackpressurePolicy struct {
	RPM   int
	TPM   int
	Burst int
}

// LimiterStore abstracts the storage for rate limiting buckets.
type LimiterStore interface {
	// Allow checks if the actor is allowed to perform an action costing 'cost'.
	// Returns true if allowed, false if rate limited.
	// Also returns the remaining tokens or an error.
	Allow(ctx context.Context, actorID string, policy BackpressurePolicy, cost int) (bool, error)
}

// TokenBucket implements a thread-safe token bucket rate limiter.
type TokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func NewTokenBucket(ratePerSec float64, capacity int) *TokenBucket {
	return &TokenBucket{
		tokens:     float64(capacity),
		capacity:   float64(capacity),
		refillRate: ratePerSec,
		lastRefill: time.Now(),
	}
}

func (tb *TokenBucket) Allow(cost int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()

	// Refill
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.lastRefill = now

	// Consume
	if tb.tokens >= float64(cost) {
		tb.tokens -= float64(cost)
		return true
	}
	return false
}

// EvaluateBackpressure checks if the actor is permitted to proceed using the provided store.
// If store is nil, it denies by default (fail closed) or allows (fail open) - let's fail closed for safety.
func EvaluateBackpressure(ctx context.Context, store LimiterStore, actorID string, policy BackpressurePolicy) error {
	if store == nil {
		return fmt.Errorf("backpressure: no limiter store configured")
	}

	allowed, err := store.Allow(ctx, actorID, policy, 1)
	if err != nil {
		return fmt.Errorf("backpressure check failed: %w", err)
	}
	if !allowed {
		return fmt.Errorf("backpressure: rate limit exceeded for %s", actorID)
	}
	return nil
}

// InMemoryLimiterStore for testing/MVP
// InMemoryLimiterStore for testing/single-instance deployments.
type InMemoryLimiterStore struct {
	mu      sync.Mutex
	buckets map[string]*TokenBucket
}

func NewInMemoryLimiterStore() *InMemoryLimiterStore {
	return &InMemoryLimiterStore{
		buckets: make(map[string]*TokenBucket),
	}
}

func (s *InMemoryLimiterStore) Allow(ctx context.Context, actorID string, policy BackpressurePolicy, cost int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tb, exists := s.buckets[actorID]
	if !exists {
		// RPM to Rate/Sec
		rate := float64(policy.RPM) / 60.0
		// Default to RPM/60 if 0? No, assume config is valid.
		if rate <= 0 {
			rate = 1 // Safe fallback
		}
		tb = NewTokenBucket(rate, policy.Burst)
		s.buckets[actorID] = tb
	}

	return tb.Allow(cost), nil
}
