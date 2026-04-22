package serving

import (
	"context"
	"errors"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/agents"
)

var ErrFallbackExhausted = errors.New("serving: all inference fallback pools exhausted")

// InferenceProfile dictates the infrastructure boundaries and cache expectations 
// for a specific agentic lane.
type InferenceProfile struct {
	Role            agents.AgentRole
	PrimaryPolicy   KVCachePolicy
	FallbackPolicy  KVCachePolicy
	ContextWindow   int
}

// DefaultProfiles binds the canonical MAMA roster to their respective KV cache optimizations.
var DefaultProfiles = map[agents.AgentRole]InferenceProfile{
	agents.RoleExplore: {
		Role:           agents.RoleExplore,
		PrimaryPolicy:  KVPolicyQJLLike,
		FallbackPolicy: KVPolicyFP8,
		ContextWindow:  64000,
	},
	agents.RolePlanner: {
		Role:           agents.RolePlanner,
		PrimaryPolicy:  KVPolicyFP8,
		FallbackPolicy: KVPolicyFP16,
		ContextWindow:  32000,
	},
	agents.RoleCritic: {
		Role:           agents.RoleCritic,
		PrimaryPolicy:  KVPolicyFP16,
		FallbackPolicy: KVPolicyFP16,
		ContextWindow:  16000,
	},
	// Replay chains are historically massive; we push extreme compression bounds here.
	agents.RoleWorldModel: {
		Role:           agents.RoleWorldModel,
		PrimaryPolicy:  KVPolicyTurboQuant,
		FallbackPolicy: KVPolicyQJLLike,
		ContextWindow:  128000,
	},
}

// DegradationEngine wraps an inference call and handles automatic fallback if the primary cache faults.
type DegradationEngine struct {
	profile InferenceProfile
}

func NewDegradationEngine(role agents.AgentRole) *DegradationEngine {
	profile, exists := DefaultProfiles[role]
	if !exists {
		// Secure default: If role mapping is missing, baseline at fp16
		profile = InferenceProfile{
			Role:           role,
			PrimaryPolicy:  KVPolicyFP16,
			FallbackPolicy: KVPolicyFP16,
			ContextWindow:  8000,
		}
	}
	return &DegradationEngine{profile: profile}
}

// Execute wraps an arbitrary inference closure, attempting Primary then falling back.
func (d *DegradationEngine) Execute(ctx context.Context, sampleFn func(policy KVCachePolicy) error) error {
	// Attempt aggressive quantization first
	err := sampleFn(d.profile.PrimaryPolicy)
	if err == nil {
		return nil
	}

	// If primary is identical to fallback, we have no degradation runway left
	if d.profile.PrimaryPolicy == d.profile.FallbackPolicy {
		return errors.Join(err, ErrFallbackExhausted)
	}

	// Fail-soft: Re-attempt computation under more standard cache mappings
	return sampleFn(d.profile.FallbackPolicy)
}
