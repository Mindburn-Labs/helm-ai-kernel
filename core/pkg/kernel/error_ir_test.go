package kernel

import (
	"testing"
	"time"
)

func TestErrorIRBuilder(t *testing.T) {
	t.Run("Basic builder", func(t *testing.T) {
		err := NewErrorIR(ErrCodeSchemaMismatch).
			WithTitle("Schema Mismatch").
			WithDetail("Field type is incorrect").
			Build()

		if err.Title != "Schema Mismatch" {
			t.Errorf("Title = %q, want 'Schema Mismatch'", err.Title)
		}
		if err.Detail != "Field type is incorrect" {
			t.Errorf("Detail = %q, want 'Field type is incorrect'", err.Detail)
		}
		if err.HELM.ErrorCode != ErrCodeSchemaMismatch {
			t.Errorf("ErrorCode = %q, want %q", err.HELM.ErrorCode, ErrCodeSchemaMismatch)
		}
	})

	t.Run("WithStatus", func(t *testing.T) {
		err := NewErrorIR(ErrCodeUnauthorized).
			WithStatus(401).
			Build()

		if err.Status != 401 {
			t.Errorf("Status = %d, want 401", err.Status)
		}
	})

	t.Run("WithInstance", func(t *testing.T) {
		err := NewErrorIR(ErrCodeNotFound).
			WithInstance("/api/v1/resources/123").
			Build()

		if err.Instance != "/api/v1/resources/123" {
			t.Errorf("Instance = %q", err.Instance)
		}
	})

	t.Run("WithClassification", func(t *testing.T) {
		err := NewErrorIR(ErrCodeNotFound).
			WithClassification(ErrorClassCompensationRequired).
			Build()

		if err.HELM.Classification != ErrorClassCompensationRequired {
			t.Errorf("Classification = %q", err.HELM.Classification)
		}
	})

	t.Run("WithCause chain", func(t *testing.T) {
		err := NewErrorIR(ErrCodeSchemaMismatch).
			WithCause(ErrCodeCSNFViolation, "/data/timestamp").
			WithCause(ErrCodePolicyDenied, "/policy/effect").
			Build()

		if len(err.HELM.CanonicalCauseChain) != 2 {
			t.Errorf("CauseChain length = %d, want 2", len(err.HELM.CanonicalCauseChain))
		}
		if err.HELM.CanonicalCauseChain[0].At != "/data/timestamp" {
			t.Error("First cause path incorrect")
		}
	})

	t.Run("Fluent chain", func(t *testing.T) {
		err := NewErrorIR(ErrCodeTimeout).
			WithTitle("Request Timeout").
			WithDetail("Upstream did not respond").
			WithStatus(504).
			WithInstance("/effects/123").
			WithCause(ErrCodeUpstreamError, "/http/connection").
			Build()

		if err.Title != "Request Timeout" {
			t.Error("Title not set")
		}
		if err.Status != 504 {
			t.Error("Status not set")
		}
		if len(err.HELM.CanonicalCauseChain) != 1 {
			t.Error("Cause not added")
		}
	})
}

func TestExtractNamespace(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"HELM/CORE/VALIDATION/SCHEMA_MISMATCH", "CORE"},
		{"HELM/ADAPTER/XYZ/ERROR", "ADAPTER"},
		{"SHORT", "UNKNOWN"},
		{"", "UNKNOWN"},
	}

	for _, tt := range tests {
		result := extractNamespace(tt.code)
		if result != tt.expected {
			t.Errorf("extractNamespace(%q) = %q, want %q", tt.code, result, tt.expected)
		}
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		code     string
		expected ErrorClassification
	}{
		{ErrCodeTimeout, ErrorClassRetryable},
		{ErrCodeUpstreamError, ErrorClassRetryable},
		{ErrCodeConflict, ErrorClassRetryable},
		{ErrCodeIdempotency, ErrorClassIdempotentSafe},
		{ErrCodeSchemaMismatch, ErrorClassNonRetryable},
		{ErrCodeUnauthorized, ErrorClassNonRetryable},
		{ErrCodePolicyDenied, ErrorClassNonRetryable},
		{"UNKNOWN/ERROR", ErrorClassNonRetryable},
	}

	for _, tt := range tests {
		result := classifyError(tt.code)
		if result != tt.expected {
			t.Errorf("classifyError(%q) = %q, want %q", tt.code, result, tt.expected)
		}
	}
}

func TestClassificationToStatus(t *testing.T) {
	tests := []struct {
		class    ErrorClassification
		expected int
	}{
		{ErrorClassRetryable, 503},
		{ErrorClassNonRetryable, 400},
		{ErrorClassIdempotentSafe, 200},
		{ErrorClassCompensationRequired, 500},
		{"unknown", 500},
	}

	for _, tt := range tests {
		result := classificationToStatus(tt.class)
		if result != tt.expected {
			t.Errorf("classificationToStatus(%q) = %d, want %d", tt.class, result, tt.expected)
		}
	}
}

func TestDefaultBackoffPolicy(t *testing.T) {
	policy := DefaultBackoffPolicy()

	if policy.PolicyID == "" {
		t.Error("PolicyID should be set")
	}
	if policy.BaseMs <= 0 {
		t.Error("BaseMs should be positive")
	}
	if policy.MaxMs <= policy.BaseMs {
		t.Error("MaxMs should be greater than BaseMs")
	}
	if policy.MaxAttempts <= 0 {
		t.Error("MaxAttempts should be positive")
	}
}

func TestComputeBackoff(t *testing.T) {
	policy := BackoffPolicy{
		PolicyID:    "test-policy",
		BaseMs:      100,
		MaxMs:       5000,
		MaxJitterMs: 100,
		MaxAttempts: 5,
	}

	t.Run("Exponential growth", func(t *testing.T) {
		params0 := BackoffParams{
			PolicyID:     policy.PolicyID,
			EffectID:     "effect-1",
			AttemptIndex: 0,
			EnvSnapHash:  "hash1",
		}
		params1 := BackoffParams{
			PolicyID:     policy.PolicyID,
			EffectID:     "effect-1",
			AttemptIndex: 1,
			EnvSnapHash:  "hash1",
		}

		delay0 := ComputeBackoff(params0, policy)
		delay1 := ComputeBackoff(params1, policy)

		// Delay should increase (exponential backoff)
		if delay1 <= delay0 {
			t.Errorf("delay1 (%v) should be > delay0 (%v)", delay1, delay0)
		}
	})

	t.Run("Cap at max", func(t *testing.T) {
		params := BackoffParams{
			PolicyID:     policy.PolicyID,
			EffectID:     "effect-1",
			AttemptIndex: 10, // High attempt
			EnvSnapHash:  "hash1",
		}

		delay := ComputeBackoff(params, policy)
		maxDelay := time.Duration(policy.MaxMs+policy.MaxJitterMs) * time.Millisecond

		if delay > maxDelay {
			t.Errorf("delay (%v) should be capped at max (%v)", delay, maxDelay)
		}
	})

	t.Run("Deterministic jitter", func(t *testing.T) {
		params := BackoffParams{
			PolicyID:     policy.PolicyID,
			EffectID:     "effect-1",
			AttemptIndex: 0,
			EnvSnapHash:  "hash1",
		}

		delay1 := ComputeBackoff(params, policy)
		delay2 := ComputeBackoff(params, policy)

		if delay1 != delay2 {
			t.Errorf("Same params should produce same delay: %v != %v", delay1, delay2)
		}
	})
}

func TestComputeDeterministicJitter(t *testing.T) {
	params := BackoffParams{
		PolicyID:     "test-policy",
		EffectID:     "effect-1",
		AttemptIndex: 0,
		EnvSnapHash:  "hash1",
	}

	t.Run("Zero max jitter", func(t *testing.T) {
		jitter := ComputeDeterministicJitter(params, 0)
		if jitter != 0 {
			t.Errorf("Jitter should be 0 when maxJitterMs=0")
		}
	})

	t.Run("Negative max jitter", func(t *testing.T) {
		jitter := ComputeDeterministicJitter(params, -100)
		if jitter != 0 {
			t.Errorf("Jitter should be 0 when maxJitterMs<0")
		}
	})

	t.Run("Bounded jitter", func(t *testing.T) {
		maxJitter := int64(1000)
		jitter := ComputeDeterministicJitter(params, maxJitter)

		if jitter < 0 || jitter >= maxJitter {
			t.Errorf("Jitter %d should be in [0, %d)", jitter, maxJitter)
		}
	})

	t.Run("Deterministic output", func(t *testing.T) {
		jitter1 := ComputeDeterministicJitter(params, 1000)
		jitter2 := ComputeDeterministicJitter(params, 1000)

		if jitter1 != jitter2 {
			t.Errorf("Same params should produce same jitter: %d != %d", jitter1, jitter2)
		}
	})
}

func TestCreateRetryPlan(t *testing.T) {
	policy := BackoffPolicy{
		PolicyID:    "test-policy",
		BaseMs:      100,
		MaxMs:       5000,
		MaxJitterMs: 50,
		MaxAttempts: 3,
	}
	startTime := time.Now()

	plan := CreateRetryPlan("effect-123", policy, "env-hash", startTime)

	if plan.RetryPlanID == "" {
		t.Error("RetryPlanID should be set")
	}
	if plan.EffectID != "effect-123" {
		t.Error("EffectID should match")
	}
	if plan.PolicyID != policy.PolicyID {
		t.Error("PolicyID should match")
	}
	if len(plan.Schedule) != policy.MaxAttempts {
		t.Errorf("Schedule length = %d, want %d", len(plan.Schedule), policy.MaxAttempts)
	}
	if plan.MaxAttempts != policy.MaxAttempts {
		t.Error("MaxAttempts should match")
	}

	// Check schedule ordering
	for i := 1; i < len(plan.Schedule); i++ {
		if plan.Schedule[i].ScheduledAt.Before(plan.Schedule[i-1].ScheduledAt) {
			t.Error("Schedule times should be increasing")
		}
	}

	// Check expires at is after last attempt
	if !plan.ExpiresAt.After(plan.Schedule[len(plan.Schedule)-1].ScheduledAt) {
		t.Error("ExpiresAt should be after last scheduled attempt")
	}
}

func TestCompareErrors(t *testing.T) {
	err1 := NewErrorIR("AAA/ERROR").Build()
	err2 := NewErrorIR("BBB/ERROR").Build()
	err3 := NewErrorIR("AAA/ERROR").WithCause("X", "/path/a").Build()
	err4 := NewErrorIR("AAA/ERROR").WithCause("X", "/path/b").Build()

	// Different error codes
	if CompareErrors(err1, err2) >= 0 {
		t.Error("AAA should come before BBB")
	}
	if CompareErrors(err2, err1) <= 0 {
		t.Error("BBB should come after AAA")
	}

	// Same error code, different paths
	if CompareErrors(err3, err4) >= 0 {
		t.Error("/path/a should come before /path/b")
	}

	// Same error code, same paths
	if CompareErrors(err3, err3) != 0 {
		t.Error("Same error should compare equal")
	}
}

func TestSelectCanonicalError(t *testing.T) {
	t.Run("Empty slice", func(t *testing.T) {
		result := SelectCanonicalError(nil)
		if result.HELM.ErrorCode != "" {
			t.Error("Empty input should return empty ErrorIR")
		}
	})

	t.Run("Single error", func(t *testing.T) {
		err := NewErrorIR("TEST/ERROR").Build()
		result := SelectCanonicalError([]ErrorIR{err})
		if result.HELM.ErrorCode != "TEST/ERROR" {
			t.Error("Single error should be returned")
		}
	})

	t.Run("Multiple errors selects smallest", func(t *testing.T) {
		errA := NewErrorIR("AAA/ERROR").Build()
		errB := NewErrorIR("BBB/ERROR").Build()
		errC := NewErrorIR("CCC/ERROR").Build()

		result := SelectCanonicalError([]ErrorIR{errC, errA, errB})
		if result.HELM.ErrorCode != "AAA/ERROR" {
			t.Errorf("Should select smallest, got %q", result.HELM.ErrorCode)
		}
	})
}
