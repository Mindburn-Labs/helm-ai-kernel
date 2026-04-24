package governance

import (
	"context"
	"testing"
)

func TestEvaluate_FailClosed_ContextTimeout(t *testing.T) {
	pdp, err := NewCELPolicyDecisionPoint("sha256:dummy", nil)
	if err != nil {
		t.Fatalf("Failed to create PDP: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := PDPRequest{
		RequestID: "req-timeout",
		Effect:    EffectDescriptor{EffectType: "DATA_WRITE"},
	}

	resp, err := pdp.Evaluate(ctx, req)

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
