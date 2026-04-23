package kernel

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisTokenBucketScript handles the token bucket algorithm atomically in Redis.
// KEYS[1] = bucket key (e.g. "rate_limit:user:123")
// ARGV[1] = refill rate (tokens per second)
// ARGV[2] = capacity (max tokens)
// ARGV[3] = cost (tokens to consume)
// ARGV[4] = current unix timestamp (seconds, floating point or microsec precision)
var redisTokenBucketScript = redis.NewScript(`
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

-- Retrieve current state
local state = redis.call("HMGET", key, "tokens", "last_refill")
local tokens = tonumber(state[1])
local last_refill = tonumber(state[2])

-- Initialize if missing
if not tokens or not last_refill then
    tokens = capacity
    last_refill = now
end

-- Refill
local elapsed = now - last_refill
if elapsed > 0 then
    local added = elapsed * rate
    tokens = tokens + added
    if tokens > capacity then
        tokens = capacity
    end
    last_refill = now
end

-- Consume
local allowed = 0
if tokens >= cost then
    tokens = tokens - cost
    allowed = 1
end

-- Update state (expire in 60s to self-clean)
redis.call("HMSET", key, "tokens", tokens, "last_refill", last_refill)
redis.call("EXPIRE", key, 60)

return {allowed, tokens}
`)

// RedisLimiterStore implements LimiterStore using Redis.
type RedisLimiterStore struct {
	client *redis.Client
}

// NewRedisLimiterStore creates a new store backed by Redis.
func NewRedisLimiterStore(addr, password string, db int) *RedisLimiterStore {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password, // no password set
		DB:       db,       // use default DB
	})
	return &RedisLimiterStore{client: rdb}
}

// Allow executes the Lua script to check and update the token bucket.
func (s *RedisLimiterStore) Allow(ctx context.Context, actorID string, policy BackpressurePolicy, cost int) (bool, error) {
	key := fmt.Sprintf("limiter:%s", actorID)

	// Rate per second
	rate := float64(policy.RPM) / 60.0
	if rate <= 0 {
		rate = 1.0
	}
	now := float64(time.Now().UnixMicro()) / 1e6

	// Execute Script
	res, err := redisTokenBucketScript.Run(ctx, s.client, []string{key}, rate, policy.Burst, cost, now).Result()
	if err != nil {
		return false, fmt.Errorf("redis limiter error: %w", err)
	}

	results, ok := res.([]interface{})
	if !ok || len(results) != 2 {
		return false, fmt.Errorf("invalid response from lua script")
	}

	allowedVal, _ := results[0].(int64)
	// tokensVal, _ := results[1].(interface{}) // could fetch remaining if needed

	return allowedVal == 1, nil
}
