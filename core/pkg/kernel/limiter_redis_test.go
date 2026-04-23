package kernel

import (
	"context"
	"testing"
	"time"
)

// TestRedisLimiterStore_Integration requires a running Redis.
// We skip if connection fails.
func TestRedisLimiterStore_Integration(t *testing.T) {
	// Try to connect to localhost default
	store := NewRedisLimiterStore("localhost:6379", "", 0)
	ctx := context.Background()
	_, err := store.client.Ping(ctx).Result()
	if err != nil {
		t.Skip("Skipping Redis integration test: redis not available")
	}

	policy := BackpressurePolicy{RPM: 60, Burst: 1} // 1 token/sec
	actor := "test-redis-actor"

	// 1. Allow
	allowed, err := store.Allow(ctx, actor, policy, 1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Errorf("Expected allowed=true for fresh bucket")
	}

	// 2. Deny (Burst 1, refill 1/s, immediate retry)
	allowed, err = store.Allow(ctx, actor, policy, 1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Errorf("Expected allowed=false (rate limited)")
	}

	// 3. Wait and Allow
	time.Sleep(1100 * time.Millisecond)
	allowed, err = store.Allow(ctx, actor, policy, 1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Errorf("Expected allowed=true after refill")
	}
}
