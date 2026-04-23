package retry

import (
	"testing"
	"time"
)

func TestGenerateRetryPlan(t *testing.T) {
	now := time.Date(2026, 1, 30, 10, 0, 0, 0, time.UTC)

	policy := BackoffPolicy{
		PolicyID:    "default",
		BaseMs:      100,
		MaxMs:       30000,
		MaxJitterMs: 0, // Disable jitter for deterministic checks in this test
		MaxAttempts: 5,
	}

	params := BackoffParams{
		PolicyID:    "default",
		AdapterID:   "adapter1",
		EffectID:    "eff1",
		EnvSnapHash: "hash123",
	}

	plan, err := GenerateRetryPlan(params, policy, now)
	if err != nil {
		t.Fatalf("GenerateRetryPlan failed: %v", err)
	}

	if len(plan.Schedule) != 5 {
		t.Errorf("Expected 5 items in schedule, got %d", len(plan.Schedule))
	}

	// Check Attempt 0
	if plan.Schedule[0].DelayMs != 0 {
		t.Errorf("Attempt 0 delayMs = %d, want 0", plan.Schedule[0].DelayMs)
	}
	if !plan.Schedule[0].ScheduledAt.Equal(now) {
		t.Errorf("Attempt 0 time = %v, want %v", plan.Schedule[0].ScheduledAt, now)
	}

	// Check Attempt 1
	// BaseMs * 2^1 = 200 ms
	expectedDelay1 := int64(200)
	if plan.Schedule[1].DelayMs != expectedDelay1 {
		t.Errorf("Attempt 1 delayMs = %d, want %d", plan.Schedule[1].DelayMs, expectedDelay1)
	}
	expectedTime1 := now.Add(time.Duration(expectedDelay1) * time.Millisecond)
	if !plan.Schedule[1].ScheduledAt.Equal(expectedTime1) {
		t.Errorf("Attempt 1 time = %v, want %v", plan.Schedule[1].ScheduledAt, expectedTime1)
	}

	// Check Attempt 2
	// BaseMs * 2^2 = 400 ms
	expectedDelay2 := int64(400)
	if plan.Schedule[2].DelayMs != expectedDelay2 {
		t.Errorf("Attempt 2 delayMs = %d, want %d", plan.Schedule[2].DelayMs, expectedDelay2)
	}
	// Schedule time is cumulative?
	// plan.go: currentScheduledTime = currentScheduledTime.Add(delay)
	// So T2 = T1 + delay2 = (T0 + delay1) + delay2
	expectedTime2 := expectedTime1.Add(time.Duration(expectedDelay2) * time.Millisecond)
	if !plan.Schedule[2].ScheduledAt.Equal(expectedTime2) {
		t.Errorf("Attempt 2 time = %v, want %v", plan.Schedule[2].ScheduledAt, expectedTime2)
	}
}

func TestDeterministicJitter(t *testing.T) {
	policy := BackoffPolicy{PolicyID: "p1", MaxJitterMs: 1000}
	params := BackoffParams{
		PolicyID:    "p1",
		EffectID:    "e1",
		EnvSnapHash: "h1",
	}

	// Run twice, expect same result
	j1 := ComputeDeterministicJitter(params, policy)
	j2 := ComputeDeterministicJitter(params, policy)

	if j1 != j2 {
		t.Errorf("Jitter non-deterministic: %d vs %d", j1, j2)
	}

	// Change input, expect different result (likely)
	params2 := params
	params2.EffectID = "e2"
	j3 := ComputeDeterministicJitter(params2, policy)

	if j3 == j1 {
		// Small chance of collision, but unlikely enough to warn?
		t.Logf("Warning: Jitter collision for different inputs (could be chance)")
	}
}
