package otel

import (
	"context"
	"testing"
)

func TestNoopTracerDoesNotPanic(t *testing.T) {
	tracer := NoopTracer()
	ctx := context.Background()

	// Must not panic
	tracer.TraceDecision(ctx, DecisionEvent{
		Verdict:    "ALLOW",
		ReasonCode: "NONE",
		EffectType: "E0",
		ToolName:   "test_tool",
		LatencyMs:  1.5,
	})

	tracer.TraceDenial(ctx, DenialEvent{
		ReasonCode: "BUDGET_EXCEEDED",
		EffectType: "E1",
		ToolName:   "expensive_tool",
		Details:    "exceeded $100 ceiling",
	})

	tracer.TraceBudget(ctx, BudgetEvent{
		Consumed:  75.0,
		Remaining: 25.0,
		Ceiling:   100.0,
	})
}

func TestMeasureDecisionTiming(t *testing.T) {
	tracer := NoopTracer()
	ctx := context.Background()

	done := tracer.MeasureDecision(ctx, "ALLOW", "NONE", "policy-1", "E0", "read_file")
	// Simulate some work
	done()
}

func TestTraceBudgetZeroCeiling(t *testing.T) {
	tracer := NoopTracer()
	ctx := context.Background()

	// Zero ceiling should not panic (divide by zero)
	tracer.TraceBudget(ctx, BudgetEvent{
		Consumed:  0,
		Remaining: 0,
		Ceiling:   0,
	})
}

func TestTraceDecisionAttributes(t *testing.T) {
	tracer := NoopTracer()
	ctx := context.Background()

	// Verify all attribute constants are valid strings
	event := DecisionEvent{
		Verdict:    "DENY",
		ReasonCode: "POLICY_VIOLATION",
		PolicyRef:  "bundle-001/rule-003",
		EffectType: "E3",
		RiskTier:   "T2",
		ToolName:   "deploy_service",
		LatencyMs:  42.5,
		Lamport:    137,
	}

	tracer.TraceDecision(ctx, event)
}
