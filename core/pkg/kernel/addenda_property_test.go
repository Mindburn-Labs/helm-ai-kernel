//go:build property
// +build property

package kernel_test

import (
	"encoding/json"
	"math/rand"
	"testing"
	"testing/quick"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
)

func quickConfig(maxCount int) *quick.Config {
	return &quick.Config{MaxCount: maxCount, Rand: rand.New(rand.NewSource(1))}
}

func positiveMod(n, m int) int {
	n %= m
	if n < 0 {
		return -n
	}
	return n
}

func TestMerkleTreeDeterminism(t *testing.T) {
	err := quick.Check(func(keys []string, values []string) bool {
		obj := make(map[string]any)
		for i := 0; i < len(keys) && i < len(values); i++ {
			if keys[i] != "" {
				obj[keys[i]] = values[i]
			}
		}
		if len(obj) == 0 {
			return true
		}

		builder := kernel.NewMerkleTreeBuilder()
		tree1, err1 := builder.BuildTree(obj)
		tree2, err2 := builder.BuildTree(obj)
		if err1 != nil || err2 != nil {
			return err1 != nil && err2 != nil
		}
		return tree1.Root == tree2.Root
	}, quickConfig(100))
	if err != nil {
		t.Fatal(err)
	}
}

func TestMerkleProofVerification(t *testing.T) {
	err := quick.Check(func(a, b, c string) bool {
		obj := map[string]any{"a": a, "b": b, "c": c}
		builder := kernel.NewMerkleTreeBuilder()
		tree, err := builder.BuildTree(obj)
		if err != nil {
			return true
		}
		for _, leaf := range tree.Leaves {
			proof, err := tree.GenerateProof(leaf.Path)
			if err != nil || !kernel.VerifyProof(*proof, tree.Root) {
				return false
			}
		}
		return true
	}, quickConfig(50))
	if err != nil {
		t.Fatal(err)
	}
}

func TestBackoffDeterminism(t *testing.T) {
	err := quick.Check(func(effectID, envHash string, attempt int) bool {
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
			AttemptIndex: positiveMod(attempt, 10),
			EnvSnapHash:  envHash,
		}
		return kernel.ComputeBackoff(params, policy) == kernel.ComputeBackoff(params, policy)
	}, quickConfig(100))
	if err != nil {
		t.Fatal(err)
	}
}

func TestBackoffMonotonicity(t *testing.T) {
	err := quick.Check(func(effectID, envHash string) bool {
		policy := kernel.BackoffPolicy{
			PolicyID:    "mono-test",
			BaseMs:      100,
			MaxMs:       100000,
			MaxJitterMs: 50,
			MaxAttempts: 10,
		}
		var delays []time.Duration
		for i := 0; i < 5; i++ {
			delays = append(delays, kernel.ComputeBackoff(kernel.BackoffParams{
				PolicyID:     policy.PolicyID,
				EffectID:     effectID,
				AttemptIndex: i,
				EnvSnapHash:  envHash,
			}, policy))
		}
		return delays[4] > delays[0]
	}, quickConfig(50))
	if err != nil {
		t.Fatal(err)
	}
}

func TestRetryPlanDeterminism(t *testing.T) {
	err := quick.Check(func(effectID, envHash string) bool {
		policy := kernel.BackoffPolicy{
			PolicyID:    "retry-test",
			BaseMs:      100,
			MaxMs:       5000,
			MaxJitterMs: 100,
			MaxAttempts: 5,
		}
		start := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
		plan1 := kernel.CreateRetryPlan(effectID, policy, envHash, start)
		plan2 := kernel.CreateRetryPlan(effectID, policy, envHash, start)
		if plan1.RetryPlanID != plan2.RetryPlanID || len(plan1.Schedule) != len(plan2.Schedule) {
			return false
		}
		for i := range plan1.Schedule {
			if plan1.Schedule[i].DelayMs != plan2.Schedule[i].DelayMs {
				return false
			}
		}
		return true
	}, quickConfig(50))
	if err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalErrorSelectionDeterminism(t *testing.T) {
	errorCodes := []string{
		"HELM/CORE/VALIDATION/SCHEMA_MISMATCH",
		"HELM/CORE/VALIDATION/CSNF_VIOLATION",
		"HELM/CORE/AUTH/UNAUTHORIZED",
		"HELM/CORE/EFFECT/TIMEOUT",
	}
	err := quick.Check(func(indices []int) bool {
		if len(indices) < 2 {
			return true
		}
		var errors []kernel.ErrorIR
		for _, idx := range indices {
			errors = append(errors, kernel.NewErrorIR(errorCodes[positiveMod(idx, len(errorCodes))]).
				WithTitle("Test Error").
				Build())
		}
		selected1 := kernel.SelectCanonicalError(errors)
		selected2 := kernel.SelectCanonicalError(errors)
		return selected1.HELM.ErrorCode == selected2.HELM.ErrorCode
	}, quickConfig(100))
	if err != nil {
		t.Fatal(err)
	}
}

func TestTimestampNormalizationDeterminism(t *testing.T) {
	err := quick.Check(func(year, month, day, hour, min, sec int) bool {
		ts := time.Date(
			2000+positiveMod(year, 100),
			time.Month(1+positiveMod(month, 12)),
			1+positiveMod(day, 28),
			positiveMod(hour, 24),
			positiveMod(min, 60),
			positiveMod(sec, 60),
			0,
			time.UTC,
		).Format(time.RFC3339)
		norm1, err1 := kernel.NormalizeTimestamp(ts)
		norm2, err2 := kernel.NormalizeTimestamp(ts)
		if err1 != nil || err2 != nil {
			return err1 != nil && err2 != nil
		}
		return norm1 == norm2
	}, quickConfig(50))
	if err != nil {
		t.Fatal(err)
	}
}

func TestNullStrippingIdempotency(t *testing.T) {
	err := quick.Check(func(keys []string, values []string) bool {
		obj := make(map[string]any)
		for i := 0; i < len(keys) && i < len(values); i++ {
			if keys[i] == "" {
				continue
			}
			if i%3 == 0 {
				obj[keys[i]] = nil
			} else {
				obj[keys[i]] = values[i]
			}
		}
		stripped1 := kernel.StripNulls(obj)
		stripped2 := kernel.StripNulls(stripped1)
		bytes1, _ := json.Marshal(stripped1)
		bytes2, _ := json.Marshal(stripped2)
		return string(bytes1) == string(bytes2)
	}, quickConfig(50))
	if err != nil {
		t.Fatal(err)
	}
}

func TestMerkleLeafOrdering(t *testing.T) {
	err := quick.Check(func(keys []string) bool {
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
		for i := 1; i < len(tree.Leaves); i++ {
			if tree.Leaves[i-1].Path >= tree.Leaves[i].Path {
				return false
			}
		}
		return true
	}, quickConfig(50))
	if err != nil {
		t.Fatal(err)
	}
}
