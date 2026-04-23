package governance

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/types"
)

// PolicyEngine is the single point of truth for all "Allow/Deny" decisions.
// It replaces the legacy RBAC/ABAC engines with a unified CEL-based evaluator.
type PolicyEngine struct {
	mu          sync.RWMutex
	env         *cel.Env
	policySet   map[string]cel.Program
	definitions map[string]string // ID -> CEL Source
}

// NewPolicyEngine initializes the CEL environment.
func NewPolicyEngine() (*PolicyEngine, error) {
	// Define standard attributes available in all policies
	env, err := cel.NewEnv(
		cel.VariableDecls(
			decls.NewVariable("action", types.StringType),
			decls.NewVariable("resource", types.StringType),
			decls.NewVariable("principal", types.StringType),
			decls.NewVariable("context", types.NewMapType(types.StringType, types.DynType)),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL env: %w", err)
	}

	return &PolicyEngine{
		env:         env,
		policySet:   make(map[string]cel.Program),
		definitions: make(map[string]string),
	}, nil
}

// LoadPolicy compiles and registers a policy.
func (pe *PolicyEngine) LoadPolicy(policyID, source string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	ast, issues := pe.env.Compile(source)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("policy compilation failed: %w", issues.Err())
	}

	prg, err := pe.env.Program(ast)
	if err != nil {
		return fmt.Errorf("program construction failed: %w", err)
	}

	pe.policySet[policyID] = prg
	pe.definitions[policyID] = source
	return nil
}

// ListDefinitions returns a copy of all loaded policy definitions (ID → source).
func (pe *PolicyEngine) ListDefinitions() map[string]string {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	out := make(map[string]string, len(pe.definitions))
	for k, v := range pe.definitions {
		out[k] = v
	}
	return out
}

// Evaluate checks a request against a specific policy (or all if policyID is empty).
// Returns a DecisionRecord.
func (pe *PolicyEngine) Evaluate(ctx context.Context, policyID string, req contracts.AccessRequest) (*contracts.DecisionRecord, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	decision := &contracts.DecisionRecord{
		ID:        fmt.Sprintf("dec-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		SubjectID: req.PrincipalID,
		Action:    req.Action,
		Resource:  req.ResourceID,
		Verdict:   "DENY", // Default deny
	}

	// Prepare CEL input
	input := map[string]interface{}{
		"action":    req.Action,
		"resource":  req.ResourceID,
		"principal": req.PrincipalID,
		"context":   req.Context,
	}

	// 1. Specific Policy Evaluation
	if policyID != "" {
		prg, exists := pe.policySet[policyID]
		if !exists {
			decision.Reason = fmt.Sprintf("Policy %s not found", policyID)
			return decision, nil
		}

		out, _, err := prg.Eval(input)
		if err != nil {
			decision.Reason = fmt.Sprintf("Evaluation error: %v", err)
			return decision, nil // Fail closed
		}

		if allowed, ok := out.Value().(bool); ok && allowed {
			decision.Verdict = "ALLOW"
			decision.Reason = fmt.Sprintf("Allowed by policy %s", policyID)
		} else {
			decision.Verdict = "DENY"
			decision.Reason = fmt.Sprintf("Denied by policy %s", policyID)
		}
		return decision, nil
	}

	// 2. Global Evaluation (if no specific policy requested, check all? Or deny?)
	// For MVP, we deny if no policy specified.
	decision.Reason = "No specific policy requested"
	return decision, nil
}

// EvaluateInline compiles and evaluates an ad-hoc CEL expression against the provided
// variables. This is the governance-level convenience for inline policy checks (e.g.,
// "risk_score < 80") without requiring pre-registration via LoadPolicy.
// Returns true if the expression evaluates to a boolean true, false otherwise.
// Fail-closed: any error in compilation or evaluation returns (false, err).
func (pe *PolicyEngine) EvaluateInline(expr string, vars map[string]interface{}) (bool, error) {
	// Build a dynamic CEL environment from the provided variable keys.
	envOpts := make([]cel.EnvOption, 0, len(vars))
	for k := range vars {
		envOpts = append(envOpts, cel.Variable(k, cel.DynType))
	}

	env, err := cel.NewEnv(envOpts...)
	if err != nil {
		return false, fmt.Errorf("failed to create inline CEL env: %w", err)
	}

	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return false, fmt.Errorf("inline policy compilation failed: %w", issues.Err())
	}

	prg, err := env.Program(ast)
	if err != nil {
		return false, fmt.Errorf("inline program construction failed: %w", err)
	}

	out, _, err := prg.Eval(vars)
	if err != nil {
		return false, fmt.Errorf("inline evaluation failed: %w", err)
	}

	allowed, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("inline expression did not evaluate to bool")
	}
	return allowed, nil
}
