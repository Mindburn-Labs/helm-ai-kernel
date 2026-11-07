package governance

import (
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policybundles"
	"github.com/google/cel-go/cel"
)

// PolicyEngine is the single point of truth for all "Allow/Deny" decisions.
// It replaces the legacy RBAC/ABAC engines with a unified CEL-based evaluator.
type PolicyEngine struct {
	mu                      sync.RWMutex
	env                     *cel.Env
	agentSafetyEnv          *cel.Env
	policySet               map[string]cel.Program
	definitions             map[string]string // ID -> CEL Source
	agentSafetyPrograms     map[string]cel.Program
	agentSafetyRules        []policybundles.PolicyRule
	agentSafetyBundleHash   string
	agentSafetyBaselineID   string
	agentSafetyBaselineName string
}
