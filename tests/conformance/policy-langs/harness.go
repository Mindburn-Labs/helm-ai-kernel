// Package policylangs implements the cross-language policy equivalence
// harness for HELM. The harness loads a single logical rule expressed in
// CEL, OPA/Rego, and Cedar form, evaluates each rendition against the
// same DecisionRequest, and reports the per-language verdict.
//
// Workstream F / F1 — Phase 3 of the helm-ai-kernel 100% SOTA execution plan.
//
// Why a hand-rolled CEL leg here:
// the policybundles registry advertises CEL but does not yet route CEL
// compile through it (the existing celcheck path owns that surface).
// Until those two paths merge, the harness builds a minimal CEL evaluator
// against the canonical DecisionRequest map shape so the equivalence
// suite can exercise all three front-ends through one codepath.
package policylangs

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	cedarfront "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policybundles/cedar"
	regofront "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policybundles/rego"
)

// Verdicts. Kept identical to the front-end packages so a string compare
// is byte-exact across all three languages.
const (
	VerdictAllow = "ALLOW"
	VerdictDeny  = "DENY"
)

// EquivalenceRequest is the canonical input the harness feeds every
// evaluator. Each language adapter shapes this struct into its native
// input form (CEL map, Rego input object, Cedar request + context record).
type EquivalenceRequest struct {
	Principal string `json:"principal"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Role      string `json:"role"`
	RiskTier  string `json:"risk_tier"`
}

// PolicyTriple is one logical rule expressed in all three languages.
type PolicyTriple struct {
	Name  string
	CEL   string
	Rego  string
	Cedar string
}

// Evaluators holds prepared, language-specific evaluators for one triple.
// Construction is up-front and amortized across many requests so property
// tests can drive thousands of inputs without re-parsing.
type Evaluators struct {
	cel   cel.Program
	rego  *regofront.Evaluator
	cedar *cedarfront.Evaluator
}

// Build prepares evaluators for the three languages of one triple. CEL
// is parsed and program-built; Rego is OPA-compiled with HELM's restricted
// capabilities; Cedar is parsed and prepared with no entities (rules only
// reference action/context to stay equivalence-safe).
func Build(ctx context.Context, t PolicyTriple) (*Evaluators, error) {
	celProg, err := buildCEL(t.CEL)
	if err != nil {
		return nil, fmt.Errorf("cel: %w", err)
	}

	regoBundle, err := regofront.Compile(t.Rego, regofront.CompileOptions{
		BundleID: "equiv-" + t.Name,
		Name:     t.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("rego compile: %w", err)
	}
	regoEv, err := regofront.NewEvaluator(ctx, regoBundle)
	if err != nil {
		return nil, fmt.Errorf("rego evaluator: %w", err)
	}

	cedarBundle, err := cedarfront.Compile(t.Cedar, cedarfront.CompileOptions{
		BundleID: "equiv-" + t.Name,
		Name:     t.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("cedar compile: %w", err)
	}
	cedarEv, err := cedarfront.NewEvaluator(ctx, cedarBundle)
	if err != nil {
		return nil, fmt.Errorf("cedar evaluator: %w", err)
	}

	return &Evaluators{cel: celProg, rego: regoEv, cedar: cedarEv}, nil
}

// EvalCEL runs the CEL program against the canonical request map.
func (e *Evaluators) EvalCEL(req EquivalenceRequest) (string, error) {
	out, _, err := e.cel.Eval(map[string]interface{}{
		"principal": req.Principal,
		"action":    req.Action,
		"resource":  req.Resource,
		"role":      req.Role,
		"risk_tier": req.RiskTier,
	})
	if err != nil {
		return VerdictDeny, fmt.Errorf("cel eval: %w", err)
	}
	return verdictFromCEL(out), nil
}

// EvalRego shapes the request into the Rego input map and dispatches.
// A boolean true result becomes ALLOW; any non-allow shape becomes DENY.
func (e *Evaluators) EvalRego(ctx context.Context, req EquivalenceRequest) (string, error) {
	d, err := e.rego.Evaluate(ctx, &regofront.DecisionRequest{
		Principal: req.Principal,
		Action:    req.Action,
		Resource:  req.Resource,
		Context: map[string]interface{}{
			"role":      req.Role,
			"risk_tier": req.RiskTier,
		},
	})
	if err != nil {
		return VerdictDeny, fmt.Errorf("rego eval: %w", err)
	}
	return d.Verdict, nil
}

// EvalCedar wraps the Cedar evaluator. The harness uses bare action
// strings and lets cedar's evaluator wrap them as Action::"<name>"; the
// principal/resource go through the same default-wrap path. Cedar
// policies in this corpus reference `action` and `context` only, so the
// concrete principal/resource UIDs do not change the outcome.
func (e *Evaluators) EvalCedar(ctx context.Context, req EquivalenceRequest) (string, error) {
	d, err := e.cedar.Evaluate(ctx, &cedarfront.DecisionRequest{
		Principal: req.Principal,
		Action:    req.Action,
		Resource:  req.Resource,
		Context: map[string]interface{}{
			"role":      req.Role,
			"risk_tier": req.RiskTier,
		},
	})
	if err != nil {
		return VerdictDeny, fmt.Errorf("cedar eval: %w", err)
	}
	return d.Verdict, nil
}

// EvalAll returns the three verdicts in (cel, rego, cedar) order. A
// non-nil err is returned only when an evaluator itself fails; a DENY
// verdict from a rule is not an error.
func (e *Evaluators) EvalAll(ctx context.Context, req EquivalenceRequest) (cel, rego, cedar string, err error) {
	cv, err := e.EvalCEL(req)
	if err != nil {
		return cv, "", "", err
	}
	rv, err := e.EvalRego(ctx, req)
	if err != nil {
		return cv, rv, "", err
	}
	dv, err := e.EvalCedar(ctx, req)
	if err != nil {
		return cv, rv, dv, err
	}
	return cv, rv, dv, nil
}

// buildCEL parses a CEL boolean expression against the canonical
// EquivalenceRequest variable shape and returns a runnable Program.
// Type-check warnings are tolerated; the cross-language suite cares
// about runtime equivalence, not type inference fidelity.
func buildCEL(src string) (cel.Program, error) {
	env, err := cel.NewEnv(
		cel.Variable("principal", cel.StringType),
		cel.Variable("action", cel.StringType),
		cel.Variable("resource", cel.StringType),
		cel.Variable("role", cel.StringType),
		cel.Variable("risk_tier", cel.StringType),
	)
	if err != nil {
		return nil, err
	}
	ast, iss := env.Parse(src)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	checked, iss := env.Check(ast)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	prog, err := env.Program(checked)
	if err != nil {
		return nil, err
	}
	return prog, nil
}

// verdictFromCEL coerces a CEL evaluation result into the canonical
// ALLOW/DENY string. Truthy booleans map to ALLOW, everything else
// (including evaluation errors that produced a value) to DENY so the
// harness fails closed in step with the kernel.
func verdictFromCEL(v ref.Val) string {
	if v == nil {
		return VerdictDeny
	}
	if b, ok := v.(types.Bool); ok && bool(b) {
		return VerdictAllow
	}
	return VerdictDeny
}
