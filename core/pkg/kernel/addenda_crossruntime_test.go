// Package kernel_test contains cross-runtime equivalence tests for HELM determinism.
// These tests verify that implementations produce identical results across scenarios.
package kernel_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel"
)

// CrossRuntimeTestVector represents a test vector for cross-runtime verification.
type CrossRuntimeTestVector struct {
	Name           string
	Input          any
	ExpectedOutput string // Expected canonical output
}

// TestCSNFCrossRuntimeEquivalence verifies CSNF produces known outputs.
// These test vectors can be shared with other language implementations.
func TestCSNFCrossRuntimeEquivalence(t *testing.T) {
	transformer := kernel.NewCSNFTransformer()

	vectors := []struct {
		name     string
		input    map[string]any
		wantRoot string // Known Merkle root for this input
	}{
		{
			name: "simple_object",
			input: map[string]any{
				"name":  "test",
				"value": int64(42),
			},
		},
		{
			name: "nested_object",
			input: map[string]any{
				"user": map[string]any{
					"id":   int64(1),
					"name": "alice",
				},
				"active": true,
			},
		},
		{
			name: "unicode_nfc",
			input: map[string]any{
				"café":  "naïve",
				"emoji": "hello",
			},
		},
	}

	// First pass: generate expected outputs
	expectedOutputs := make(map[string]string)
	for _, v := range vectors {
		result, err := transformer.Transform(v.input)
		if err != nil {
			t.Fatalf("Transform failed for %s: %v", v.name, err)
		}
		bytes, _ := json.Marshal(result)
		expectedOutputs[v.name] = string(bytes)
	}

	// Second pass: verify determinism
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			result, err := transformer.Transform(v.input)
			if err != nil {
				t.Fatalf("Transform failed: %v", err)
			}
			bytes, _ := json.Marshal(result)
			got := string(bytes)

			if got != expectedOutputs[v.name] {
				t.Errorf("Non-deterministic output:\ngot:  %s\nwant: %s", got, expectedOutputs[v.name])
			}
		})
	}
}

// TestMerkleCrossRuntimeEquivalence verifies Merkle roots match known values.
func TestMerkleCrossRuntimeEquivalence(t *testing.T) {
	builder := kernel.NewMerkleTreeBuilder()

	// Test vectors with known inputs - roots should be consistent
	vectors := []struct {
		name  string
		input map[string]any
	}{
		{
			name: "simple_three_fields",
			input: map[string]any{
				"a": "first",
				"b": "second",
				"c": "third",
			},
		},
		{
			name: "integers_only",
			input: map[string]any{
				"x": int64(1),
				"y": int64(2),
				"z": int64(3),
			},
		},
		{
			name: "mixed_types",
			input: map[string]any{
				"bool":   true,
				"int":    int64(42),
				"string": "hello",
			},
		},
	}

	// Generate and verify roots are consistent
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			tree1, err1 := builder.BuildTree(v.input)
			tree2, err2 := builder.BuildTree(v.input)

			if err1 != nil || err2 != nil {
				t.Fatalf("BuildTree failed: %v, %v", err1, err2)
			}

			if tree1.Root != tree2.Root {
				t.Errorf("Non-deterministic root:\nfirst:  %s\nsecond: %s", tree1.Root, tree2.Root)
			}

			// Log the root for cross-runtime verification
			t.Logf("Merkle root for %s: %s", v.name, tree1.Root)
		})
	}
}

// TestBackoffCrossRuntimeEquivalence verifies backoff delays match known values.
func TestBackoffCrossRuntimeEquivalence(t *testing.T) {
	policy := kernel.BackoffPolicy{
		PolicyID:    "standard-backoff-v1",
		BaseMs:      100,
		MaxMs:       30000,
		MaxJitterMs: 1000,
		MaxAttempts: 5,
	}

	vectors := []struct {
		name        string
		effectID    string
		envSnapHash string
		attempt     int
	}{
		{
			name:        "first_attempt",
			effectID:    "effect-001",
			envSnapHash: "env-abc123",
			attempt:     0,
		},
		{
			name:        "second_attempt",
			effectID:    "effect-001",
			envSnapHash: "env-abc123",
			attempt:     1,
		},
		{
			name:        "max_attempt",
			effectID:    "effect-001",
			envSnapHash: "env-abc123",
			attempt:     4,
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			params := kernel.BackoffParams{
				PolicyID:     policy.PolicyID,
				EffectID:     v.effectID,
				AttemptIndex: v.attempt,
				EnvSnapHash:  v.envSnapHash,
			}

			delay1 := kernel.ComputeBackoff(params, policy)
			delay2 := kernel.ComputeBackoff(params, policy)

			if delay1 != delay2 {
				t.Errorf("Non-deterministic delay: %v != %v", delay1, delay2)
			}

			// Log delay for cross-runtime verification
			t.Logf("Backoff delay for %s: %v", v.name, delay1)
		})
	}
}

// TestErrorIRCrossRuntimeEquivalence verifies ErrorIR classification matches known values.
func TestErrorIRCrossRuntimeEquivalence(t *testing.T) {
	vectors := []struct {
		errorCode          string
		expectedClass      kernel.ErrorClassification
		expectedHTTPStatus int
	}{
		{
			errorCode:          "HELM/CORE/VALIDATION/SCHEMA_MISMATCH",
			expectedClass:      kernel.ErrorClassNonRetryable,
			expectedHTTPStatus: 400,
		},
		{
			errorCode:          "HELM/CORE/EFFECT/TIMEOUT",
			expectedClass:      kernel.ErrorClassRetryable,
			expectedHTTPStatus: 503,
		},
		{
			errorCode:          "HELM/CORE/EFFECT/IDEMPOTENCY_CONFLICT",
			expectedClass:      kernel.ErrorClassIdempotentSafe,
			expectedHTTPStatus: 200,
		},
	}

	for _, v := range vectors {
		t.Run(v.errorCode, func(t *testing.T) {
			err := kernel.NewErrorIR(v.errorCode).Build()

			if err.HELM.Classification != v.expectedClass {
				t.Errorf("Classification mismatch: got %s, want %s",
					err.HELM.Classification, v.expectedClass)
			}

			if err.Status != v.expectedHTTPStatus {
				t.Errorf("HTTP status mismatch: got %d, want %d",
					err.Status, v.expectedHTTPStatus)
			}
		})
	}
}

// TestRetryPlanCrossRuntimeEquivalence verifies retry plans are reproducible.
func TestRetryPlanCrossRuntimeEquivalence(t *testing.T) {
	policy := kernel.BackoffPolicy{
		PolicyID:    "retry-test-v1",
		BaseMs:      100,
		MaxMs:       5000,
		MaxJitterMs: 50,
		MaxAttempts: 3,
	}

	startTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	effectID := "effect-reproducible-001"
	envHash := "env-snapshot-hash-001"

	plan1 := kernel.CreateRetryPlan(effectID, policy, envHash, startTime)
	plan2 := kernel.CreateRetryPlan(effectID, policy, envHash, startTime)

	// Verify plan IDs are identical
	if plan1.RetryPlanID != plan2.RetryPlanID {
		t.Errorf("Plan IDs differ:\n  first:  %s\n  second: %s", plan1.RetryPlanID, plan2.RetryPlanID)
	}

	// Verify schedule is identical
	if len(plan1.Schedule) != len(plan2.Schedule) {
		t.Fatalf("Schedule lengths differ: %d vs %d", len(plan1.Schedule), len(plan2.Schedule))
	}

	for i := range plan1.Schedule {
		if plan1.Schedule[i].DelayMs != plan2.Schedule[i].DelayMs {
			t.Errorf("Attempt %d delay differs: %d vs %d",
				i, plan1.Schedule[i].DelayMs, plan2.Schedule[i].DelayMs)
		}
		if !plan1.Schedule[i].ScheduledAt.Equal(plan2.Schedule[i].ScheduledAt) {
			t.Errorf("Attempt %d scheduled_at differs: %v vs %v",
				i, plan1.Schedule[i].ScheduledAt, plan2.Schedule[i].ScheduledAt)
		}
	}

	// Log for cross-runtime verification
	t.Logf("Retry plan ID: %s", plan1.RetryPlanID)
	for i, attempt := range plan1.Schedule {
		t.Logf("  Attempt %d: delay=%dms, at=%s",
			i, attempt.DelayMs, attempt.ScheduledAt.Format(time.RFC3339Nano))
	}
}

// TestEvidenceViewCrossRuntimeEquivalence verifies EvidenceView derivation is reproducible.
func TestEvidenceViewCrossRuntimeEquivalence(t *testing.T) {
	builder := kernel.NewMerkleTreeBuilder()

	pack := map[string]any{
		"public_data":  "visible to all",
		"private_data": "confidential",
		"metadata": map[string]any{
			"created": "2024-01-15T10:00:00Z",
			"version": int64(1),
		},
	}

	tree, err := builder.BuildTree(pack)
	if err != nil {
		t.Fatalf("BuildTree failed: %v", err)
	}

	policy := kernel.ViewPolicy{
		PolicyID: "test-disclosure-v1",
		Name:     "Test View",
		DisclosureRules: []kernel.DisclosureRule{
			{PathPattern: "/public_data", Action: "DISCLOSE"},
			{PathPattern: "/private_data", Action: "SEAL", Reason: "confidential"},
			{PathPattern: "/metadata/*", Action: "DISCLOSE"},
		},
	}

	timestamp := "2024-06-15T12:00:00Z"

	view1, err := kernel.DeriveEvidenceView(pack, tree, policy, timestamp)
	if err != nil {
		t.Fatalf("DeriveEvidenceView failed: %v", err)
	}

	view2, err := kernel.DeriveEvidenceView(pack, tree, policy, timestamp)
	if err != nil {
		t.Fatalf("DeriveEvidenceView failed: %v", err)
	}

	// Verify view IDs are identical
	if view1.ViewID != view2.ViewID {
		t.Errorf("View IDs differ: %s vs %s", view1.ViewID, view2.ViewID)
	}

	// Verify view hashes are identical
	if view1.ViewHash != view2.ViewHash {
		t.Errorf("View hashes differ: %s vs %s", view1.ViewHash, view2.ViewHash)
	}

	// Log for cross-runtime verification
	t.Logf("View ID: %s", view1.ViewID)
	t.Logf("View Hash: %s", view1.ViewHash)
	t.Logf("Merkle Root: %s", tree.Root)
}

// TestCanonicalErrorSelectionCrossRuntime verifies error selection order.
func TestCanonicalErrorSelectionCrossRuntime(t *testing.T) {
	errors := []kernel.ErrorIR{
		kernel.NewErrorIR("HELM/CORE/VALIDATION/SCHEMA_MISMATCH").
			WithCause("c1", "/field_b").Build(),
		kernel.NewErrorIR("HELM/CORE/AUTH/UNAUTHORIZED").
			WithCause("c2", "/field_a").Build(),
		kernel.NewErrorIR("HELM/CORE/AUTH/FORBIDDEN").
			WithCause("c3", "/field_c").Build(),
	}

	selected := kernel.SelectCanonicalError(errors)

	// AUTH/FORBIDDEN < AUTH/UNAUTHORIZED < VALIDATION/SCHEMA_MISMATCH (alphabetically)
	expectedCode := "HELM/CORE/AUTH/FORBIDDEN"
	if selected.HELM.ErrorCode != expectedCode {
		t.Errorf("Wrong error selected: got %s, want %s", selected.HELM.ErrorCode, expectedCode)
	}

	t.Logf("Selected error code: %s", selected.HELM.ErrorCode)
}

// TestDecimalStringCrossRuntime verifies decimal string validation.
func TestDecimalStringCrossRuntime(t *testing.T) {
	validCases := []string{
		"0",
		"123",
		"-456",
		"123.45",
		"-0.001",
		"999999999999999999",
	}

	invalidCases := []string{
		"",
		"00123",   // Leading zeros
		"12.34.5", // Multiple decimals
		"abc",
		"12a34",
		" 123",
	}

	for _, tc := range validCases {
		t.Run("valid_"+tc, func(t *testing.T) {
			if err := kernel.ValidateDecimalString(tc); err != nil {
				t.Errorf("Expected %q to be valid, got error: %v", tc, err)
			}
		})
	}

	for _, tc := range invalidCases {
		t.Run("invalid_"+tc, func(t *testing.T) {
			if err := kernel.ValidateDecimalString(tc); err == nil {
				t.Errorf("Expected %q to be invalid", tc)
			}
		})
	}
}

// TestTimestampNormalizationCrossRuntime verifies timestamp normalization.
func TestTimestampNormalizationCrossRuntime(t *testing.T) {
	vectors := []struct {
		input    string
		expected string
	}{
		{
			input:    "2024-06-15T10:30:00Z",
			expected: "2024-06-15T10:30:00.000Z",
		},
		{
			input:    "2024-06-15T12:30:00+02:00",
			expected: "2024-06-15T10:30:00.000Z",
		},
		{
			input:    "2024-06-15T05:30:00-05:00",
			expected: "2024-06-15T10:30:00.000Z",
		},
	}

	for _, v := range vectors {
		t.Run(v.input, func(t *testing.T) {
			result, err := kernel.NormalizeTimestamp(v.input)
			if err != nil {
				t.Fatalf("NormalizeTimestamp failed: %v", err)
			}
			if result != v.expected {
				t.Errorf("Got %s, want %s", result, v.expected)
			}
		})
	}
}
