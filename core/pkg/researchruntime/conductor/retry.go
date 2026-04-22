package conductor

import (
	"math"
	"time"
)

// RetryPolicy defines exponential back-off parameters for task execution.
type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
}

// DefaultRetryPolicy returns the standard 3-attempt exponential back-off policy.
func DefaultRetryPolicy() *RetryPolicy {
	return &RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   2 * time.Second,
	}
}

// ShouldRetry reports whether attempt (0-based) is within the allowed budget.
func (p *RetryPolicy) ShouldRetry(attempt int) bool {
	return attempt < p.MaxAttempts
}

// Delay returns the back-off duration for a given attempt number (0-based).
// Delay grows as BaseDelay * 2^attempt.
func (p *RetryPolicy) Delay(attempt int) time.Duration {
	return p.BaseDelay * time.Duration(math.Pow(2, float64(attempt)))
}
