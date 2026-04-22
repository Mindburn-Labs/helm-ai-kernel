package retry

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

type BackoffParams struct {
	PolicyID     string
	AdapterID    string
	EffectID     string
	AttemptIndex int
	EnvSnapHash  string
}

type BackoffPolicy struct {
	PolicyID    string
	BaseMs      int64
	MaxMs       int64
	MaxJitterMs int64
	MaxAttempts int
}

// ComputeBackoff returns the delay for a specific attempt using deterministic jitter.
func ComputeBackoff(params BackoffParams, policy BackoffPolicy) time.Duration {
	// 1. Exponential Backoff
	// delay = base * 2^attempt
	// Use bit shift for power of 2
	factor := int64(1)
	if params.AttemptIndex > 0 {
		if params.AttemptIndex > 30 {
			// Avoid overflow, cap exponent
			factor = 1 << 30
		} else {
			factor = 1 << params.AttemptIndex
		}
	}

	baseDelay := policy.BaseMs * factor

	// Cap at MaxMs
	if baseDelay > policy.MaxMs {
		baseDelay = policy.MaxMs
	}

	// 2. Deterministic Jitter
	jitter := ComputeDeterministicJitter(params, policy)

	return time.Duration(baseDelay+jitter) * time.Millisecond
}

func ComputeDeterministicJitter(params BackoffParams, policy BackoffPolicy) int64 {
	// PRF seeded by inputs
	seed := fmt.Sprintf("%s:%s:%s:%d:%s",
		params.PolicyID,
		params.AdapterID,
		params.EffectID,
		params.AttemptIndex,
		params.EnvSnapHash,
	)

	hash := sha256.Sum256([]byte(seed))
	// Use first 8 bytes as uint64
	jitterBasis := binary.BigEndian.Uint64(hash[:8])

	if policy.MaxJitterMs == 0 {
		return 0
	}

	return int64(jitterBasis % uint64(policy.MaxJitterMs)) //nolint:gosec // MaxJitterMs is always positive
}
