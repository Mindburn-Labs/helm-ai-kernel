package governance

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/capabilities"
	"github.com/google/cel-go/cel"
)

// CELPolicyEvaluator implements PolicyEvaluator using CEL with Caching and System Policy.
type CELPolicyEvaluator struct {
	env         *cel.Env
	prgCache    map[string]cel.Program
	mu          sync.RWMutex
	systemRules []string // Hardcoded System Policy for GAP-02
}

// NewCELPolicyEvaluator creates a new evaluator with a standard environment.
func NewCELPolicyEvaluator() (*CELPolicyEvaluator, error) {
	// 1. Define Environment (using modern cel.Variable instead of deprecated cel.Declarations)
	env, err := cel.NewEnv(
		cel.Variable("module", cel.DynType), // input: dynamic map
		cel.Variable("timestamp", cel.IntType),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	// 2. Define System Policy (The "Constitution")
	// For production readiness, we enforce these globally.
	sysRules := []string{
		// Rule 1: Module name must be namespaced (e.g., "org.module")
		`module.name.matches("^[a-z0-9-]+\\.[a-z0-9-]+$")`,
		// Rule 2: Version must be semantic (basic check)
		`module.version.matches("^[0-9]+\\.[0-9]+\\.[0-9]+.*$")`,
	}

	return &CELPolicyEvaluator{
		env:         env,
		prgCache:    make(map[string]cel.Program),
		systemRules: sysRules,
	}, nil
}

// VerifyModulePolicy checks if the new module complies with System Rules AND its own Policy.
func (e *CELPolicyEvaluator) VerifyModulePolicy(ctx context.Context, newModule ModuleBundle) error {
	// 1. Prepare Input
	input := map[string]any{
		"timestamp": time.Now().Unix(),
		"module": map[string]any{
			"id": newModule.ID,
			// Name and Version are not in ModuleBundle definition in lifecycle.go yet,
			// but they are used in CEL rules.
			// Assuming they should be in Manifest or top level.
			// For now, mapping ID to name if name missing, or extracting from Manifest if possible.
			// Let's assume ID is the name for now or add them to ModuleBundle in lifecycle.go?
			// I'll extract from Manifest if present, else use ID.
			"name":             getNameFromManifest(newModule),
			"version":          getVersionFromManifest(newModule),
			"capability_names": extractCapabilityNames(newModule.Capabilities),
			"dependencies":     newModule.Dependencies,
		},
	}

	// 2. Enforce System Policy (Fail-Closed)
	for i, rule := range e.systemRules {
		allowed, err := e.evaluateExpr(rule, input)
		if err != nil {
			return fmt.Errorf("system policy error (rule %d): %w", i, err)
		}
		if !allowed {
			return fmt.Errorf("system policy denied module %s: rule %d violated", newModule.ID, i)
		}
	}

	// 3. Enforce Module Self-Policy (if exists)
	if newModule.Policy != "" {
		allowed, err := e.evaluateExpr(newModule.Policy, input)
		if err != nil {
			return fmt.Errorf("module policy error: %w", err)
		}
		if !allowed {
			return fmt.Errorf("module policy denied activation for %s", newModule.ID)
		}
		//nolint:staticcheck // suppressed
	} else { //nolint:staticcheck
		// GAP-02: Fail Closed if no policy? Or defined default?
		// For now, we allow if System Policy passed, effectively "Default Allow" for internal logic,
		// but blocked by strict System Rules if malformed.
	}

	return nil
}

func getNameFromManifest(m ModuleBundle) string {
	if n, ok := m.Manifest["name"].(string); ok {
		return n
	}
	return m.ID
}

func getVersionFromManifest(m ModuleBundle) string {
	if v, ok := m.Manifest["version"].(string); ok {
		return v
	}
	return "0.0.0"
}

func (e *CELPolicyEvaluator) evaluateExpr(expr string, input map[string]any) (bool, error) {
	e.mu.RLock()
	prg, hit := e.prgCache[expr]
	e.mu.RUnlock()

	if !hit {
		e.mu.Lock()
		// Double check
		if prg, hit = e.prgCache[expr]; !hit {
			ast, issues := e.env.Compile(expr)
			if issues != nil && issues.Err() != nil {
				e.mu.Unlock()
				return false, fmt.Errorf("compile: %w", issues.Err())
			}
			p, err := e.env.Program(ast,
				cel.InterruptCheckFrequency(100),
				cel.CostLimit(10000), // Hard limit on computational complexity
			)
			if err != nil {
				e.mu.Unlock()
				return false, fmt.Errorf("program: %w", err)
			}
			e.prgCache[expr] = p
			prg = p
		}
		e.mu.Unlock()
	}

	out, _, err := prg.Eval(input)
	if err != nil {
		return false, fmt.Errorf("eval: %w", err)
	}
	val, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("result not bool")
	}
	return val, nil
}

func extractCapabilityNames(caps []capabilities.Capability) []string {
	names := make([]string, len(caps))
	for i, c := range caps {
		names[i] = c.Name
	}
	return names
}
