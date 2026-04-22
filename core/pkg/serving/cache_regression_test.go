package serving_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/agents"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/serving"
)

// TestDegradationHarness simulates an ARC long-horizon Replay agent attempting
// multiple context compression states and verifies fail-soft boundaries.
func TestDegradationHarness(t *testing.T) {
	engine := serving.NewDegradationEngine(agents.RoleWorldModel)
	
	ctx := context.Background()

	var usedPolicies []serving.KVCachePolicy

	// Simulate engine block where TurboQuant backend is not installed, forcing degrade
	mockKernel := func(policy serving.KVCachePolicy) error {
		usedPolicies = append(usedPolicies, policy)
		if policy == serving.KVPolicyTurboQuant {
			return errors.New("CUDA kernel missing for extreme quantization")
		}
		return nil
	}

	err := engine.Execute(ctx, mockKernel)
	if err != nil {
		t.Fatalf("expected degradation engine to recover cleanly, got: %v", err)
	}

	if len(usedPolicies) != 2 {
		t.Fatalf("expected exactly two execution attempts, got %d", len(usedPolicies))
	}

	if usedPolicies[0] != serving.KVPolicyTurboQuant {
		t.Errorf("expected primary rollout to attempt TurboQuant, got %v", usedPolicies[0])
	}
	
	if usedPolicies[1] != serving.KVPolicyQJLLike {
		t.Errorf("expected fallback rollout to downgrade to QJL, got %v", usedPolicies[1])
	}
	
	t.Log("KVCache serving fail-soft gracefully degraded from TurboQuant to QJL without crashing the planner loop.")
}
