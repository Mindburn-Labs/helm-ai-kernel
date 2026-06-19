package prg

import (
	"fmt"
	"sync"

	pkg_artifact "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policycel"
	"github.com/google/cel-go/cel"
)

// PolicyEngine evaluates PRG requirements against context.
type PolicyEngine struct {
	env      *cel.Env
	prgCache map[string]cel.Program
	mu       sync.RWMutex
}

func NewPolicyEngine() (*PolicyEngine, error) {
	// Define standard environment variables for policies
	// We expose a single "input" map for maximum flexibility (Node 8 pattern)
	opts := []cel.EnvOption{
		cel.Variable("input", cel.MapType(cel.StringType, cel.DynType)),
	}
	opts = append(opts, policycel.TaintEnvOptions()...)
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL env: %w", err)
	}
	return &PolicyEngine{
		env:      env,
		prgCache: make(map[string]cel.Program),
	}, nil
}

func (pe *PolicyEngine) compileProgram(expression string) (cel.Program, error) {
	expression = policycel.RewritePRGTaintContains(expression)

	pe.mu.RLock()
	prg, hit := pe.prgCache[expression]
	pe.mu.RUnlock()

	if !hit {
		pe.mu.Lock()
		if prg, hit = pe.prgCache[expression]; !hit {
			ast, issues := pe.env.Compile(expression)
			if issues != nil && issues.Err() != nil {
				pe.mu.Unlock()
				return nil, fmt.Errorf("CEL compile error: %w", issues.Err())
			}

			p, err := pe.env.Program(ast)
			if err != nil {
				pe.mu.Unlock()
				return nil, fmt.Errorf("CEL program error: %w", err)
			}
			pe.prgCache[expression] = p
			prg = p
		}
		pe.mu.Unlock()
	}

	return prg, nil
}

func (pe *PolicyEngine) Evaluate(expression string, input map[string]interface{}) (bool, error) {
	prg, err := pe.compileProgram(expression)
	if err != nil {
		return false, err
	}

	out, _, err := prg.Eval(input)
	if err != nil {
		return false, fmt.Errorf("CEL eval error: %w", err)
	}

	allowed, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("result not boolean")
	}

	return allowed, nil
}

// CompileRequirementSet precompiles and caches every CEL expression in a
// requirement tree. Callers that install immutable policy snapshots can use it
// to surface expression errors once at load time rather than at decision time.
func (pe *PolicyEngine) CompileRequirementSet(rs RequirementSet) error {
	for _, req := range rs.Requirements {
		if req.Expression == "" {
			continue
		}
		if _, err := pe.compileProgram(req.Expression); err != nil {
			return fmt.Errorf("compile error in req %s: %w", req.ID, err)
		}
	}
	for _, child := range rs.Children {
		if err := pe.CompileRequirementSet(child); err != nil {
			return err
		}
	}
	return nil
}

// CompileGraph precompiles every CEL expression in a policy graph.
func (pe *PolicyEngine) CompileGraph(graph *Graph) error {
	if graph == nil {
		return nil
	}
	for actionID, rule := range graph.Rules {
		if err := pe.CompileRequirementSet(rule); err != nil {
			return fmt.Errorf("compile rule %s: %w", actionID, err)
		}
	}
	return nil
}

// EvaluateRequirementSet recursively evaluates a RequirementSet against the input.
func (pe *PolicyEngine) EvaluateRequirementSet(rs RequirementSet, input map[string]interface{}) (bool, error) {
	activation := map[string]interface{}{"input": input, "taint": input["taint"]}
	return pe.evaluateRequirementSet(rs, input, activation)
}

func (pe *PolicyEngine) evaluateRequirementSet(rs RequirementSet, input map[string]interface{}, activation map[string]interface{}) (bool, error) {
	if len(rs.Requirements) == 0 && len(rs.Children) == 0 {
		return true, nil
	}

	logic := rs.Logic
	if logic == "" {
		logic = AND
	}

	switch logic {
	case AND:
		for _, req := range rs.Requirements {
			result, err := pe.evaluateRequirement(req, input, activation)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil
			}
		}
		for _, child := range rs.Children {
			result, err := pe.evaluateRequirementSet(child, input, activation)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil
			}
		}
		return true, nil
	case OR:
		for _, req := range rs.Requirements {
			result, err := pe.evaluateRequirement(req, input, activation)
			if err != nil {
				return false, err
			}
			if result {
				return true, nil
			}
		}
		for _, child := range rs.Children {
			result, err := pe.evaluateRequirementSet(child, input, activation)
			if err != nil {
				return false, err
			}
			if result {
				return true, nil
			}
		}
		return false, nil
	case NOT:
		for _, req := range rs.Requirements {
			result, err := pe.evaluateRequirement(req, input, activation)
			if err != nil {
				return false, err
			}
			if !result {
				return true, nil
			}
		}
		for _, child := range rs.Children {
			result, err := pe.evaluateRequirementSet(child, input, activation)
			if err != nil {
				return false, err
			}
			if !result {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("unknown logic operator: %s", rs.Logic)
	}
}

func (pe *PolicyEngine) evaluateRequirement(req Requirement, input map[string]interface{}, activation map[string]interface{}) (bool, error) {
	// If CEL expression exists, it takes precedence.
	if req.Expression != "" {
		prog, err := pe.compileProgram(req.Expression)
		if err != nil {
			return false, fmt.Errorf("compile error in req %s: %w", req.ID, err)
		}
		out, _, err := prog.Eval(activation)
		if err != nil {
			return false, fmt.Errorf("eval error in req %s: %w", req.ID, err)
		}
		val, ok := out.Value().(bool)
		if !ok {
			return false, fmt.Errorf("req %s did not return bool", req.ID)
		}
		return val, nil
	}

	// Legacy ArtifactType check (for backward compatibility and simple policies).
	if req.ArtifactType != "" {
		artifacts, ok := input["artifacts"].([]*pkg_artifact.ArtifactEnvelope)
		if !ok {
			return false, nil
		}
		for _, art := range artifacts {
			if art.Type == req.ArtifactType {
				return true, nil
			}
		}
		return false, nil
	}

	// No expression and no artifact type = always pass (open policy).
	return true, nil
}

func combineResults(logic LogicOperator, results []bool) (bool, error) {
	if logic == AND || logic == "" {
		for _, r := range results {
			if !r {
				return false, nil
			}
		}
		return true, nil
	}
	if logic == OR {
		for _, r := range results {
			if r {
				return true, nil
			}
		}
		return false, nil
	}
	if logic == NOT {
		allTrue := true
		for _, r := range results {
			if !r {
				allTrue = false
				break
			}
		}
		return !allTrue, nil
	}
	return false, fmt.Errorf("unknown logic operator: %s", logic)
}
