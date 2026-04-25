package retry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

	planID := deterministicRetryPlanID(params, policy, schedule)
	return &RetryPlanRef{
		RetryPlanID: planID,
		EffectID:    params.EffectID,
		PolicyID:    policy.PolicyID,
		Schedule:    schedule,
		MaxAttempts: policy.MaxAttempts,
		CreatedAt:   now,
		ExpiresAt:   currentScheduledTime.Add(time.Duration(policy.MaxMs+policy.MaxJitterMs) * time.Millisecond),
	}, nil
}

func deterministicRetryPlanID(params BackoffParams, policy BackoffPolicy, schedule []RetrySchedule) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s:%s:%s:%s:%d:%d:%d:%d",
		params.PolicyID,
		params.AdapterID,
		params.EffectID,
		params.EnvSnapHash,
		policy.BaseMs,
		policy.MaxMs,
		policy.MaxJitterMs,
		policy.MaxAttempts,
	)
	for _, item := range schedule {
		_, _ = fmt.Fprintf(h, ":%d:%d:%s", item.AttemptIndex, item.DelayMs, item.ScheduledAt.UTC().Format(time.RFC3339Nano))
	}
	return "retry-" + hex.EncodeToString(h.Sum(nil))[:24]
}
