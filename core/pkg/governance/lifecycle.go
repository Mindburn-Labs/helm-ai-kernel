package governance

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capabilities"
)

// ModuleBundle represents a compiled module artifact.
type ModuleBundle struct {
	ID           string                    `json:"id"`
	Dependencies []string                  `json:"dependencies"`
	ContentHash  string                    `json:"content_hash"`
	Manifest     map[string]any            `json:"manifest"` // Generic manifest
	CompiledAt   time.Time                 `json:"compiled_at"`
	Capabilities []capabilities.Capability `json:"capabilities"`
	Policy       string                    `json:"policy"`
}

// ActionActivateModule is a governed action to promote a module to active configuration.
type ActionActivateModule struct {
	ModuleBundle   ModuleBundle `json:"module_bundle"`
	CanaryStrategy string       `json:"canary_strategy"` // "IMMEDIATE", "BLUE_GREEN"
}

// LifecycleManager handles state transitions.
type LifecycleManager struct {
	registry interface {
		ApplyPhenotype(modules []ModuleBundle) error
	}
	policyEngine PolicyEvaluator
}

// PolicyEvaluator abstracts the decision engine for governance.
type PolicyEvaluator interface {
	// VerifyModulePolicy checks if the new module complies with the policy.
	VerifyModulePolicy(ctx context.Context, newModule ModuleBundle) error
}

// SimplePolicyEvaluator is a concrete implementation returning simple decisions.
type SimplePolicyEvaluator struct{}
