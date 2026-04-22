package kernel

import (
	"context"
	"testing"
	"time"
)

func TestTokenBucket_Throttling_I36(t *testing.T) {
	// 60 requests per minute = 1 per second. Burst 1.
	store := NewInMemoryLimiterStore()
	policy := BackpressurePolicy{RPM: 60, Burst: 1}

	actor := "test-actor"

	// 1. First request should pass
	// 1. First request should pass
	if allowed, err := store.Allow(context.Background(), actor, policy, 1); err != nil || !allowed {
		t.Fatalf("First request failed: allowed=%v, err=%v", allowed, err)
	}

	// 2. Second request immediately after should fail (empty bucket, refill rate 1/s)
	// 2. Second request immediately after should fail (empty bucket, refill rate 1/s)
	if allowed, _ := store.Allow(context.Background(), actor, policy, 1); allowed {
		t.Errorf("Second request allowed, expected error (rate limit)")
	}

	// 3. Wait 1.1s (refill 1 token)
	time.Sleep(1100 * time.Millisecond)

	// 4. Request should pass again
	// 4. Request should pass again
	if allowed, err := store.Allow(context.Background(), actor, policy, 1); err != nil || !allowed {
		t.Errorf("Third request (after wait) failed: allowed=%v, err=%v", allowed, err)
	}
}
