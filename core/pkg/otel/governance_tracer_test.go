package otel

import (
	"context"
	"net/http"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/observability"
	otelapi "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
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

// makeRecordingTracer wires a GovernanceTracer to an in-memory exporter so
// tests can assert attributes on emitted spans.
func makeRecordingTracer(t *testing.T) (*GovernanceTracer, *tracetest.InMemoryExporter) {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	otelapi.SetTracerProvider(tp)
	gt := NoopTracer()
	gt.tracer = tp.Tracer("helm.governance.test")
	return gt, exp
}

func attrMap(kvs []attribute.KeyValue) map[string]attribute.Value {
	m := make(map[string]attribute.Value, len(kvs))
	for _, kv := range kvs {
		m[string(kv.Key)] = kv.Value
	}
	return m
}

// TestTraceDecisionEmitsGenAIKeys asserts the decision span carries the OTel
// GenAI semconv attributes plus the helm.* governance attributes. This is the
// stable wire contract every SIEM exporter relies on.
func TestTraceDecisionEmitsGenAIKeys(t *testing.T) {
	tracer, exp := makeRecordingTracer(t)
	ctx := context.Background()

	tracer.TraceDecision(ctx, DecisionEvent{
		Verdict:            "ALLOW",
		ReasonCode:         "NONE",
		PolicyRef:          "bundle-001/rule-001",
		EffectType:         "E0",
		ToolName:           "search_web",
		LatencyMs:          1.2,
		Lamport:            42,
		GenAISystem:        observability.GenAISystemOpenAI,
		GenAIRequestModel:  "gpt-4o",
		GenAIOperationName: observability.GenAIOperationToolCall,
		GenAIToolCallID:    "call_abc123",
		GenAIInputTokens:   120,
		GenAIOutputTokens:  35,
		GenAIFinishReason:  "tool_calls",
		GenAIResponseModel: "gpt-4o-2024-08-06",
		GenAIResponseID:    "chatcmpl-xyz",
		HelmPolicyID:       "bundle-001/rule-001",
		HelmProofNodeID:    "pg-node-99",
		HelmCorrelationID:  "corr-7",
		HelmReceiptID:      "rcpt-7",
		HelmTenantID:       "tenant-A",
	})

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	got := attrMap(spans[0].Attributes)

	expected := map[string]string{
		observability.GenAISystem:               "openai",
		observability.GenAIRequestModel:         "gpt-4o",
		observability.GenAIOperationName:        "tool_call",
		observability.GenAIToolName:             "search_web",
		observability.GenAIToolCallID:           "call_abc123",
		observability.GenAIResponseFinishReason: "tool_calls",
		observability.GenAIResponseModel:        "gpt-4o-2024-08-06",
		observability.GenAIResponseID:           "chatcmpl-xyz",
		observability.HelmVerdict:               "ALLOW",
		observability.HelmReasonCode:            "NONE",
		observability.HelmPolicyID:              "bundle-001/rule-001",
		observability.HelmProofNodeID:           "pg-node-99",
		observability.HelmCorrelationID:         "corr-7",
		observability.HelmReceiptID:             "rcpt-7",
		observability.HelmTenantID:              "tenant-A",
	}
	for k, want := range expected {
		v, ok := got[k]
		if !ok {
			t.Errorf("missing attribute %q", k)
			continue
		}
		if v.AsString() != want {
			t.Errorf("attribute %q = %q, want %q", k, v.AsString(), want)
		}
	}

	if v, ok := got[observability.GenAIUsageInputTokens]; !ok || v.AsInt64() != 120 {
		t.Errorf("input_tokens = %v, want 120", v)
	}
	if v, ok := got[observability.GenAIUsageOutputTokens]; !ok || v.AsInt64() != 35 {
		t.Errorf("output_tokens = %v, want 35", v)
	}
}

// TestTraceDenialEmitsGenAIKeys mirrors the decision-key contract for denials.
func TestTraceDenialEmitsGenAIKeys(t *testing.T) {
	tracer, exp := makeRecordingTracer(t)
	ctx := context.Background()

	tracer.TraceDenial(ctx, DenialEvent{
		ReasonCode:         "BUDGET_EXCEEDED",
		PolicyRef:          "bundle-001/budget",
		EffectType:         "E2",
		ToolName:           "deploy_service",
		GenAISystem:        observability.GenAISystemAnthropic,
		GenAIRequestModel:  "claude-3-5-sonnet",
		GenAIOperationName: observability.GenAIOperationToolCall,
		GenAIToolCallID:    "toolu_xyz",
		HelmPolicyID:       "bundle-001/budget",
		HelmProofNodeID:    "pg-node-100",
		HelmCorrelationID:  "corr-8",
		HelmTenantID:       "tenant-B",
	})

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	got := attrMap(spans[0].Attributes)

	expected := map[string]string{
		observability.GenAISystem:        "anthropic",
		observability.GenAIRequestModel:  "claude-3-5-sonnet",
		observability.GenAIOperationName: "tool_call",
		observability.GenAIToolName:      "deploy_service",
		observability.GenAIToolCallID:    "toolu_xyz",
		observability.HelmVerdict:        "DENY",
		observability.HelmReasonCode:     "BUDGET_EXCEEDED",
		observability.HelmPolicyID:       "bundle-001/budget",
		observability.HelmProofNodeID:    "pg-node-100",
		observability.HelmCorrelationID:  "corr-8",
		observability.HelmTenantID:       "tenant-B",
	}
	for k, want := range expected {
		v, ok := got[k]
		if !ok {
			t.Errorf("missing attribute %q", k)
			continue
		}
		if v.AsString() != want {
			t.Errorf("attribute %q = %q, want %q", k, v.AsString(), want)
		}
	}
}

// TestTraceGenAIToolCallSpanName asserts the span name and attribute set for
// the dedicated GenAI tool-call helper.
func TestTraceGenAIToolCallSpanName(t *testing.T) {
	tracer, exp := makeRecordingTracer(t)
	ctx := context.Background()

	tracer.TraceGenAIToolCall(ctx, GenAIToolCallEvent{
		System:        observability.GenAISystemBedrock,
		RequestModel:  "anthropic.claude-3-5-sonnet-20241022",
		OperationName: observability.GenAIOperationToolCall,
		ToolName:      "list_buckets",
		ToolCallID:    "corr-9",
		InputTokens:   80,
		OutputTokens:  16,
		FinishReason:  "tool_calls",
		Verdict:       "ALLOW",
		PolicyID:      "bundle-002/aws",
		ProofNodeID:   "pg-node-101",
		CorrelationID: "corr-9",
		TenantID:      "tenant-C",
		LatencyMs:     2.4,
	})

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Name != "gen_ai.tool_call" {
		t.Errorf("span name = %q, want %q", spans[0].Name, "gen_ai.tool_call")
	}
	got := attrMap(spans[0].Attributes)
	if v, ok := got[observability.GenAISystem]; !ok || v.AsString() != "aws.bedrock" {
		t.Errorf("system = %v, want aws.bedrock", v)
	}
	if v, ok := got[observability.GenAIToolCallID]; !ok || v.AsString() != "corr-9" {
		t.Errorf("tool_call_id = %v, want corr-9", v)
	}
	if v, ok := got[observability.HelmCorrelationID]; !ok || v.AsString() != "corr-9" {
		t.Errorf("correlation_id = %v, want corr-9 (must equal tool_call_id)", v)
	}
}

// TestInjectExtractTraceparent verifies W3C traceparent round-trips so the
// proxy can propagate context to upstream model providers.
func TestInjectExtractTraceparent(t *testing.T) {
	tracer, _ := makeRecordingTracer(t)
	ctx, span := tracer.tracer.Start(context.Background(), "test.parent")
	defer span.End()

	headers := http.Header{}
	InjectTraceparent(ctx, headers)
	if headers.Get("traceparent") == "" {
		t.Fatal("expected traceparent header to be set after Inject")
	}

	extracted := ExtractTraceparent(context.Background(), headers)
	if extracted == nil {
		t.Fatal("ExtractTraceparent returned nil context")
	}
}
