package rego

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Evaluator wraps a prepared OPA query for repeated, low-latency
// evaluation. Construct it via NewEvaluator(); the prepared query is
// thread-safe and safe to share across goroutines.
type Evaluator struct {
	bundle  *CompiledBundle
	prepped rego.PreparedEvalQuery
}

// NewEvaluator prepares the underlying OPA query for evaluation. The
// HELM-restricted capabilities are re-applied to defeat any tampering
// between Compile and load time.
func NewEvaluator(ctx context.Context, b *CompiledBundle) (*Evaluator, error) {
	if b == nil {
		return nil, fmt.Errorf("rego: nil bundle")
	}
	caps, _, err := loadCapabilities()
	if err != nil {
		return nil, err
	}
	prepped, err := rego.New(
		rego.Query(b.Query),
		rego.Module("policy.rego", b.Module),
		rego.Capabilities(caps),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("rego: prepare query: %w", err)
	}
	return &Evaluator{bundle: b, prepped: prepped}, nil
}

// Evaluate runs the prepared query against the given DecisionRequest and
// normalizes the result into a Decision.
func (e *Evaluator) Evaluate(ctx context.Context, req *DecisionRequest) (*Decision, error) {
	if req == nil {
		return nil, fmt.Errorf("rego: nil request")
	}
	input := map[string]interface{}{
		"principal": req.Principal,
		"action":    req.Action,
		"resource":  req.Resource,
		"tool":      req.Tool,
	}
	if req.Context != nil {
		input["context"] = req.Context
	}

	results, err := e.prepped.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("rego: evaluate: %w", err)
	}

	decision := &Decision{Verdict: VerdictDeny, PolicyID: e.bundle.BundleID}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		decision.Reason = "rego: no decision returned"
		return decision, nil
	}

	value := results[0].Expressions[0].Value
	switch v := value.(type) {
	case bool:
		if v {
			decision.Verdict = VerdictAllow
		} else {
			decision.Reason = "rego: policy returned false"
		}
	case map[string]interface{}:
		if verdict, ok := v["verdict"].(string); ok {
			decision.Verdict = verdict
		} else if allow, ok := v["allow"].(bool); ok {
			if allow {
				decision.Verdict = VerdictAllow
			}
		}
		if reason, ok := v["reason"].(string); ok {
			decision.Reason = reason
		}
		if ob, ok := v["obligations"].(map[string]interface{}); ok {
			decision.Obligations = ob
		}
	default:
		decision.Reason = fmt.Sprintf("rego: unsupported decision type %T", value)
	}
	return decision, nil
}
