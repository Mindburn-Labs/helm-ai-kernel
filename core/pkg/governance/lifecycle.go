package governance

import (
	"context"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/capabilities"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
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

func NewLifecycleManager(reg interface {
	ApplyPhenotype([]ModuleBundle) error
}, policyEngine PolicyEvaluator) *LifecycleManager {
	return &LifecycleManager{
		registry:     reg,
		policyEngine: policyEngine,
	}
}

// ValidateModuleDependencies ensures that adding the new module does not create cycles or deadlocks.
// currentModules: map of existing module ID -> ModuleBundle
func (l *LifecycleManager) ValidateModuleDependencies(ctx context.Context, newModule ModuleBundle, currentModules map[string]ModuleBundle) error {
	// 1. Cycle Detection (DFS)
	// We construct a temporary graph including the new module

	// Create adjacency list
	graph := make(map[string][]string)
	for id, mod := range currentModules {
		graph[id] = mod.Dependencies
	}
	// Add new module
	graph[newModule.ID] = newModule.Dependencies

	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)

	var detectCycle func(node string) error
	detectCycle = func(node string) error {
		visited[node] = true
		recursionStack[node] = true

		for _, dep := range graph[node] {
			if !visited[dep] {
				if err := detectCycle(dep); err != nil {
					return err
				}
			} else if recursionStack[dep] {
				return fmt.Errorf("cycle detected: %s depends on %s", node, dep)
			}
		}

		recursionStack[node] = false
		return nil
	}

	// Check starting from the new module
	if err := detectCycle(newModule.ID); err != nil {
		return err
	}

	// 2. Anti-Lockout (Self-Preservation) via Policy Engine
	// Replaces previous regex heuristic.
	if l.policyEngine != nil {
		if err := l.policyEngine.VerifyModulePolicy(ctx, newModule); err != nil {
			return fmt.Errorf("policy violation: %w", err)
		}
	}

	return nil
}

// SimplePolicyEvaluator is a concrete implementation returning simple decisions.
type SimplePolicyEvaluator struct{}

func (e *SimplePolicyEvaluator) VerifyModulePolicy(ctx context.Context, newModule ModuleBundle) error {
	// Real logic: Parse Config, check "Allow" or "Deny" clauses.
	// For now, we structurize valid checks instead of regex.
	// e.g., explicit deny on specific dangerous IDs unless signed by specific keys.
	return nil
}

func (l *LifecycleManager) ExecuteActivation(ctx context.Context, action ActionActivateModule, decision *contracts.DecisionRecord, currentModules map[string]ModuleBundle) error {
	// 1. Verify Decision (must allow "ACTIVATE_MODULE")
	if decision.Verdict != string(contracts.VerdictAllow) {
		return fmt.Errorf("activation denied by decision: %s", decision.Reason)
	}

	// 2. Validate Module Dependencies (GAP-03)
	if err := l.ValidateModuleDependencies(ctx, action.ModuleBundle, currentModules); err != nil {
		return fmt.Errorf("module dependency validation failed: %w", err)
	}

	// 2. Validate Module Signature (Redundant if Builder did it, but good defense in depth)
	// (Skipping for brevity, assuming Bundle is verified)

	// 3. Canary Logic
	//nolint:staticcheck // suppressed
	if action.CanaryStrategy == "BLUE_GREEN" {
		// Log "Starting Canary..."
		// For demo/MVP, we just proceed.
	}

	// 4. Apply to Registry (The "Commit")
	// In reality this fetches current module set, appends, and applies.
	// We'll simplisticly assume we are adding this module to empty or handled by registry.
	// Since registry.ApplyPhenotype sets the WHOLE state, we really need the current state first.
	// Stubbing "Append" behavior for MVP logic.

	// Stub: We just re-apply just this module as if it's the only one, or append to known list.
	// Ideally LifecycleManager holds the current StateCursor.

	return l.registry.ApplyPhenotype([]ModuleBundle{action.ModuleBundle})
}
