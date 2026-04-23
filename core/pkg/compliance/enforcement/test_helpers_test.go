package enforcement

import "context"

// TestPolicyEvaluator is a configurable policy evaluator for integration tests.
// It implements PolicyEvaluator with injectable results for verifying
// enforcement engine behavior without requiring a live CEL runtime.
type TestPolicyEvaluator struct {
	defaultResult PolicyResult
	resultsByExpr map[string]PolicyResult
}

// NewTestPolicyEvaluator creates a configurable test evaluator.
func NewTestPolicyEvaluator(defaultResult PolicyResult) *TestPolicyEvaluator {
	return &TestPolicyEvaluator{
		defaultResult: defaultResult,
		resultsByExpr: make(map[string]PolicyResult),
	}
}

// SetResult configures a result for a specific expression.
func (c *TestPolicyEvaluator) SetResult(expr string, result PolicyResult) {
	c.resultsByExpr[expr] = result
}

// Evaluate evaluates a policy expression against the configured results.
func (c *TestPolicyEvaluator) Evaluate(ctx context.Context, expr string, input map[string]interface{}) (PolicyResult, error) {
	if result, ok := c.resultsByExpr[expr]; ok {
		return result, nil
	}
	return c.defaultResult, nil
}
