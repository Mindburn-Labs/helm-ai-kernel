//go:build property
// +build property

// Package kernel_test contains property-based tests for CSNF, ErrorIR, and Merkle determinism.
package kernel_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel"
)

// TestMerkleTreeDeterminism verifies Merkle tree construction is deterministic.
// Property: BuildTree(obj) == BuildTree(obj) for any obj
func TestMerkleTreeDeterminism(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("Merkle tree construction is deterministic", prop.ForAll(
		func(keys []string, values []string) bool {
			// Build object from keys and values
			obj := make(map[string]any)
			for i := 0; i < len(keys) && i < len(values); i++ {
				if keys[i] != "" {
					obj[keys[i]] = values[i]
				}
			}
			if len(obj) == 0 {
				return true // Skip empty objects
			}

			builder := kernel.NewMerkleTreeBuilder()
			tree1, err1 := builder.BuildTree(obj)
			tree2, err2 := builder.BuildTree(obj)

			if err1 != nil && err2 != nil {
				return true // Both fail consistently
			}
			if err1 != nil || err2 != nil {
				return false // Inconsistent failure
			}

			return tree1.Root == tree2.Root
		},
		gen.SliceOf(gen.AlphaString()),
		gen.SliceOf(gen.AlphaString()),
	))

	properties.TestingRun(t)
}

// TestMerkleProofVerification verifies all generated proofs are valid.
// Property: VerifyProof(GenerateProof(path), root) == true
func TestMerkleProofVerification(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	properties.Property("Generated proofs always verify", prop.ForAll(
		func(a, b, c string) bool {
			obj := map[string]any{
				"a": a,
				"b": b,
				"c": c,
			}

			builder := kernel.NewMerkleTreeBuilder()
			tree, err := builder.BuildTree(obj)
			if err != nil {
				return true // Skip errors
			}

			// Verify proof for each leaf
			for _, leaf := range tree.Leaves {
				proof, err := tree.GenerateProof(leaf.Path)
				if err != nil {
					return false
				}
				if !kernel.VerifyProof(*proof, tree.Root) {
					return false
				}
			}

			return true
		},
		gen.AlphaString(),
		gen.AlphaString(),
		gen.AlphaString(),
	))

	properties.TestingRun(t)
}

// TestBackoffDeterminism verifies backoff calculation is deterministic.
// Property: ComputeBackoff(params) == ComputeBackoff(params)
func TestBackoffDeterminism(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("Backoff calculation is deterministic", prop.ForAll(
		func(effectID, envHash string, attempt int) bool {
			policy := kernel.BackoffPolicy{
				PolicyID:    "test-policy",
				BaseMs:      100,
				MaxMs:       10000,
				MaxJitterMs: 500,
				MaxAttempts: 10,
			}

			params := kernel.BackoffParams{
				PolicyID:     policy.PolicyID,
				EffectID:     effectID,
				AttemptIndex: attempt % 10,
				EnvSnapHash:  envHash,
			}

			delay1 := kernel.ComputeBackoff(params, policy)
			delay2 := kernel.ComputeBackoff(params, policy)

			return delay1 == delay2
		},
		gen.AlphaString(),
		gen.AlphaString(),
		gen.IntRange(0, 100),
	))

	properties.TestingRun(t)
}

// TestBackoffMonotonicity verifies delays increase with attempt index.
// Property: delay(n) <= delay(n+1) (modulo jitter bounds)
func TestBackoffMonotonicity(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	properties.Property("Backoff delays generally increase", prop.ForAll(
		func(effectID, envHash string) bool {
			policy := kernel.BackoffPolicy{
				PolicyID:    "mono-test",
				BaseMs:      100,
				MaxMs:       100000, // High max to see exponential growth
				MaxJitterMs: 50,     // Small jitter
				MaxAttempts: 10,
			}

			var delays []time.Duration
			for i := 0; i < 5; i++ {
				params := kernel.BackoffParams{
					PolicyID:     policy.PolicyID,
					EffectID:     effectID,
					AttemptIndex: i,
					EnvSnapHash:  envHash,
				}
				delays = append(delays, kernel.ComputeBackoff(params, policy))
			}

			// Allow for jitter, but base delay should grow
			// Base delays: 100, 200, 400, 800, 1600 ms
			// With jitter variation is small enough that trend should be clear
			return delays[4] > delays[0]
		},
		gen.AlphaString(),
		gen.AlphaString(),
	))

	properties.TestingRun(t)
}

// TestRetryPlanDeterminism verifies retry plan generation is deterministic.
// Property: CreateRetryPlan(effectID, policy, hash, time) == CreateRetryPlan(effectID, policy, hash, time)
func TestRetryPlanDeterminism(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	properties.Property("Retry plan generation is deterministic", prop.ForAll(
		func(effectID, envHash string) bool {
			policy := kernel.BackoffPolicy{
				PolicyID:    "retry-test",
				BaseMs:      100,
				MaxMs:       5000,
				MaxJitterMs: 100,
				MaxAttempts: 5,
			}

			startTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

			plan1 := kernel.CreateRetryPlan(effectID, policy, envHash, startTime)
			plan2 := kernel.CreateRetryPlan(effectID, policy, envHash, startTime)

			// Plans should be identical
			if plan1.RetryPlanID != plan2.RetryPlanID {
				return false
			}
			if len(plan1.Schedule) != len(plan2.Schedule) {
				return false
			}
			for i := range plan1.Schedule {
				if plan1.Schedule[i].DelayMs != plan2.Schedule[i].DelayMs {
					return false
				}
			}
			return true
		},
		gen.AlphaString(),
		gen.AlphaString(),
	))

	properties.TestingRun(t)
}

// TestCanonicalErrorSelectionDeterminism verifies error selection is deterministic.
// Property: SelectCanonicalError(errors) == SelectCanonicalError(errors)
func TestCanonicalErrorSelectionDeterminism(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	errorCodes := []string{
		"HELM/CORE/VALIDATION/SCHEMA_MISMATCH",
		"HELM/CORE/VALIDATION/CSNF_VIOLATION",
		"HELM/CORE/AUTH/UNAUTHORIZED",
		"HELM/CORE/EFFECT/TIMEOUT",
	}

	properties.Property("Error selection is deterministic", prop.ForAll(
		func(indices []int) bool {
			if len(indices) < 2 {
				return true // Skip trivial cases
			}

			var errors []kernel.ErrorIR
			for _, idx := range indices {
				code := errorCodes[idx%len(errorCodes)]
				err := kernel.NewErrorIR(code).
					WithTitle("Test Error").
					Build()
				errors = append(errors, err)
			}

			selected1 := kernel.SelectCanonicalError(errors)
			selected2 := kernel.SelectCanonicalError(errors)

			return selected1.HELM.ErrorCode == selected2.HELM.ErrorCode
		},
		gen.SliceOfN(5, gen.IntRange(0, 100)),
	))

	properties.TestingRun(t)
}

// TestTimestampNormalizationDeterminism verifies timestamp normalization is deterministic.
func TestTimestampNormalizationDeterminism(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	properties.Property("Timestamp normalization is deterministic", prop.ForAll(
		func(year, month, day, hour, min, sec int) bool {
			// Generate valid timestamp
			y := 2000 + (year % 100)
			m := 1 + (month % 12)
			d := 1 + (day % 28)
			h := hour % 24
			mi := min % 60
			s := sec % 60

			ts := time.Date(y, time.Month(m), d, h, mi, s, 0, time.UTC).Format(time.RFC3339)

			norm1, err1 := kernel.NormalizeTimestamp(ts)
			norm2, err2 := kernel.NormalizeTimestamp(ts)

			if err1 != nil && err2 != nil {
				return true
			}
			if err1 != nil || err2 != nil {
				return false
			}

			return norm1 == norm2
		},
		gen.IntRange(0, 1000),
		gen.IntRange(0, 1000),
		gen.IntRange(0, 1000),
		gen.IntRange(0, 1000),
		gen.IntRange(0, 1000),
		gen.IntRange(0, 1000),
	))

	properties.TestingRun(t)
}

// TestNullStrippingIdempotency verifies null stripping is idempotent.
func TestNullStrippingIdempotency(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	properties.Property("Null stripping is idempotent", prop.ForAll(
		func(keys []string, values []string) bool {
			obj := make(map[string]any)
			for i := 0; i < len(keys) && i < len(values); i++ {
				if keys[i] != "" {
					if i%3 == 0 {
						obj[keys[i]] = nil // Some nulls
					} else {
						obj[keys[i]] = values[i]
					}
				}
			}

			stripped1 := kernel.StripNulls(obj)
			stripped2 := kernel.StripNulls(stripped1)

			// Second strip should have no effect
			bytes1, _ := json.Marshal(stripped1)
			bytes2, _ := json.Marshal(stripped2)

			return string(bytes1) == string(bytes2)
		},
		gen.SliceOf(gen.AlphaString()),
		gen.SliceOf(gen.AlphaString()),
	))

	properties.TestingRun(t)
}

// TestMerkleLeafOrdering verifies leaves are always sorted.
func TestMerkleLeafOrdering(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 50
	properties := gopter.NewProperties(parameters)

	properties.Property("Merkle leaves are always sorted", prop.ForAll(
		func(keys []string) bool {
			obj := make(map[string]any)
			for i, k := range keys {
				if k != "" {
					obj[k] = i
				}
			}
			if len(obj) == 0 {
				return true
			}

			builder := kernel.NewMerkleTreeBuilder()
			tree, err := builder.BuildTree(obj)
			if err != nil {
				return true
			}

			// Verify leaves are sorted
			for i := 1; i < len(tree.Leaves); i++ {
				if tree.Leaves[i-1].Path >= tree.Leaves[i].Path {
					return false
				}
			}
			return true
		},
		gen.SliceOf(gen.AlphaString()),
	))

	properties.TestingRun(t)
}
