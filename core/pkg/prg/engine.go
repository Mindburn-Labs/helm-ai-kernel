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

func (pe *PolicyEngine) Evaluate(expression string, input map[string]interface{}) (bool, error) {
	expression = policycel.RewritePRGTaintContains(expression)

	prg, err := pe.programForExpression(expression)
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

func (pe *PolicyEngine) programForExpression(expression string) (cel.Program, error) {
	pe.mu.RLock()
	prg, hit := pe.prgCache[expression]
	pe.mu.RUnlock()
	if hit {
		return prg, nil
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()
	if prg, hit = pe.prgCache[expression]; hit {
		return prg, nil
	}
	ast, issues := pe.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("CEL compile error: %w", issues.Err())
	}
	prg, err := pe.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("CEL program error: %w", err)
	}
	pe.prgCache[expression] = prg
	return prg, nil
}

func (pe *PolicyEngine) WarmGraph(g *Graph) error {
	if g == nil {
		return nil
	}
	for actionID, set := range g.Rules {
		if err := pe.WarmRequirementSet(&set); err != nil {
			return fmt.Errorf("warm policy %s: %w", actionID, err)
		}
		g.Rules[actionID] = set
	}
	return nil
}

func (pe *PolicyEngine) WarmRequirementSet(rs *RequirementSet) error {
	if rs == nil {
		return nil
	}
	if err := pe.warmRequirements(rs.Requirements); err != nil {
		return err
	}
	for i := range rs.Children {
		if err := pe.WarmRequirementSet(&rs.Children[i]); err != nil {
			return err
		}
	}
	return nil
}

func (pe *PolicyEngine) warmRequirements(reqs []Requirement) error {
	for i := range reqs {
		if reqs[i].Expression == "" {
			continue
		}
		expression := policycel.RewritePRGTaintContains(reqs[i].Expression)
		prog, err := pe.programForExpression(expression)
		if err != nil {
			return fmt.Errorf("compile error in req %s: %w", reqs[i].ID, err)
		}
		reqs[i].compiledExpression = expression
		reqs[i].program = prog
	}
	return nil
}

// EvaluateRequirementSet recursively evaluates a RequirementSet against the input.
func (pe *PolicyEngine) EvaluateRequirementSet(rs RequirementSet, input map[string]interface{}) (bool, error) {
	if len(rs.Requirements) == 0 && len(rs.Children) == 0 {
		return true, nil
	}

	leafResults, err := pe.evaluateLeaves(rs.Requirements, input)
	if err != nil {
		return false, err
	}

	childResults, err := pe.evaluateChildren(rs.Children, input)
	if err != nil {
		return false, err
	}

	return combineResults(rs.Logic, append(leafResults, childResults...))
}

func (pe *PolicyEngine) evaluateLeaves(reqs []Requirement, input map[string]interface{}) ([]bool, error) {
	results := make([]bool, 0, len(reqs))
	activation := map[string]interface{}{"input": input, "taint": input["taint"]}

	for _, req := range reqs {
		// If CEL expression exists, it takes precedence
		if req.Expression != "" {
			expression := policycel.RewritePRGTaintContains(req.Expression)
			prog := req.program
			if prog == nil || req.compiledExpression != expression {
				var err error
				prog, err = pe.programForExpression(expression)
				if err != nil {
					return nil, fmt.Errorf("compile error in req %s: %w", req.ID, err)
				}
			}
			out, _, err := prog.Eval(activation)
			if err != nil {
				return nil, fmt.Errorf("eval error in req %s: %w", req.ID, err)
			}
			val, ok := out.Value().(bool)
			if !ok {
				return nil, fmt.Errorf("req %s did not return bool", req.ID)
			}
			results = append(results, val)
			continue
		}

		// Legacy ArtifactType check (for backward compatibility and simple policies)
		if req.ArtifactType != "" {
			artifacts, ok := input["artifacts"].([]*pkg_artifact.ArtifactEnvelope)
			if !ok {
				results = append(results, false)
				continue
			}
			found := false
			for _, art := range artifacts {
				if art.Type == req.ArtifactType {
					found = true
					break
				}
			}
			results = append(results, found)
			continue
		}

		// No expression and no artifact type = always pass (open policy)
		results = append(results, true)
	}
	return results, nil
}

func (pe *PolicyEngine) evaluateChildren(children []RequirementSet, input map[string]interface{}) ([]bool, error) {
	results := make([]bool, 0, len(children))
	for _, child := range children {
		val, err := pe.EvaluateRequirementSet(child, input)
		if err != nil {
			return nil, err
		}
		results = append(results, val)
	}
	return results, nil
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
