package governance

import (
	"context"
	"testing"
)

func TestEvaluate_FailClosed_ContextTimeout(t *testing.T) {
	// 1. Setup PDP (Mocked or Real)
	pdp, err := NewCELPolicyDecisionPoint("sha256:dummy", nil)
	if err != nil {
		t.Fatalf("Failed to create PDP: %v", err)
	}

	// 2. Create Context that is ALREADY canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := PDPRequest{
		RequestID: "req-timeout",
		Effect:    EffectDescriptor{EffectType: "DATA_WRITE"},
	}

	// 3. Evaluate -> Wait, implementation might not check context immediately if logic is fast
	// But strictly, a robust system *should* respect context.
	// For Band 3, we want to ensure *if* operations hang, we have a mechanism.
	// Since CEL is local CPU bound, it might finish before context check.
	// Let's rely on the design that Evaluate() is synchronous for now.
	// However, if we HAD external lookups (like verifying evidence), this matches.

	// 3. Evaluate -> Should handle canceled context
	// In a real implementation, this should return error or DENY.
	// We just want to ensure it doesn't panic and returns a valid response object or error.
	resp, err := pdp.Evaluate(ctx, req)

	// If it returns an error, we consider that a pass (system failed safely)
	// If it returns a response, it MUST be DENY.
	if err == nil {
		if resp.Decision != DecisionDeny {
			t.Errorf("Expected DENY for canceled context, got %s", resp.Decision)
		}
	}
}

func TestEvaluate_FailClosed_EmptyRequest(t *testing.T) {
	pdp, _ := NewCELPolicyDecisionPoint("sha256:dummy", nil)

	// Empty request (zero value) matches nothing
	req := PDPRequest{}

	resp, _ := pdp.Evaluate(context.Background(), req)

	if resp.Decision != DecisionDeny {
		t.Errorf("Expected DENY for empty request, got %s", resp.Decision)
	}
}

func TestEvaluate_FailClosed_UnknownIdempotency(t *testing.T) {
	pdp, _ := NewCELPolicyDecisionPoint("sha256:dummy", nil)

	// Missing critical fields should default to DENY if strict
	req := PDPRequest{
		RequestID: "req-1",
		Effect: EffectDescriptor{
			EffectType: "CRITICAL_OP",
			// Missing IdempotencyKey might be allowed in dev, but strictly?
		},
	}

	// Since we haven't loaded policies, the default hardcoded rules in `pdp.go` apply.
	// "CRITICAL_OP" is not in the allowlist -> Expect DENY.

	resp, _ := pdp.Evaluate(context.Background(), req)
	if resp.Decision != DecisionDeny {
		t.Errorf("Expected DENY for unknown/unauthorized op, got %s", resp.Decision)
	}
}

func TestEvaluate_Determinism_Repeatability(t *testing.T) {
	pdp, _ := NewCELPolicyDecisionPoint("sha256:dummy", nil)

	req := PDPRequest{
		RequestID: "req-det",
		Effect:    EffectDescriptor{EffectType: "DATA_WRITE"}, // In allowlist
	}

	// Call 1
	resp1, _ := pdp.Evaluate(context.Background(), req)

	// Call 2
	resp2, _ := pdp.Evaluate(context.Background(), req)

	if resp1.DecisionID != resp2.DecisionID {
		t.Errorf("DecisionID mismatch: %s vs %s", resp1.DecisionID, resp2.DecisionID)
	}

	if resp1.Trace.EvaluationGraphHash != resp2.Trace.EvaluationGraphHash {
		t.Errorf("GraphHash mismatch")
	}
}
