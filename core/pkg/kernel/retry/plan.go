package retry

import (
	"time"
)

type RetryPlanRef struct {
	RetryPlanID string          `json:"retry_plan_id"`
	EffectID    string          `json:"effect_id"`
	PolicyID    string          `json:"policy_id"`
	Schedule    []RetrySchedule `json:"schedule"`
	MaxAttempts int             `json:"max_attempts"`
	ExpiresAt   time.Time       `json:"expires_at"`
	CreatedAt   time.Time       `json:"created_at"`
}

type RetrySchedule struct {
	AttemptIndex int       `json:"attempt_index"`
	DelayMs      int64     `json:"delay_ms"`
	ScheduledAt  time.Time `json:"scheduled_at"`
}

// GenerateRetryPlan creates a deterministic retry plan.
func GenerateRetryPlan(params BackoffParams, policy BackoffPolicy, now time.Time) (*RetryPlanRef, error) {
	schedule := make([]RetrySchedule, policy.MaxAttempts)

	currentScheduledTime := now

	for i := 0; i < policy.MaxAttempts; i++ {
		// Clone params for this attempt
		attemptParams := params
		attemptParams.AttemptIndex = i

		var delay time.Duration
		if i == 0 {
			delay = 0
		} else {
			delay = ComputeBackoff(attemptParams, policy)
		}

		delayMs := delay.Milliseconds()

		currentScheduledTime = currentScheduledTime.Add(delay)

		schedule[i] = RetrySchedule{
			AttemptIndex: i,
			DelayMs:      delayMs,
			ScheduledAt:  currentScheduledTime,
		}
	}

	// Create Plan Object (ID generation omitted for brevity/external handling)
	return &RetryPlanRef{
		RetryPlanID: "plan_" + params.EffectID, // Placeholder ID logic
		EffectID:    params.EffectID,
		PolicyID:    policy.PolicyID,
		Schedule:    schedule,
		MaxAttempts: policy.MaxAttempts,
		CreatedAt:   now,
		ExpiresAt:   currentScheduledTime.Add(1 * time.Hour), // Arbitrary expiration buffer
	}, nil
}
