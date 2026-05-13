// Package otel provides OpenTelemetry integration for HELM governance telemetry.
//
// It exports governance decisions, denials, and budget consumption as
// OpenTelemetry traces and metrics, enabling visibility into governance
// operations through any OTel-compatible observability backend
// (Jaeger, Datadog, Grafana, Google Cloud Monitoring, etc.).
//
// Usage:
//
//	tracer, err := otel.NewGovernanceTracer(otel.Config{
//	    ServiceName: "helm-guardian",
//	    Endpoint:    "localhost:4317",
//	})
//	defer tracer.Shutdown(ctx)
//
//	tracer.TraceDecision(ctx, decision)
//	tracer.TraceDenial(ctx, denial)
package otel

import (
	"context"
	"net/http"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// ── Attribute Keys ───────────────────────────────────────────

const (
	// Decision attributes
	AttrDecisionVerdict    = "helm.decision.verdict"
	AttrDecisionReasonCode = "helm.decision.reason_code"
	AttrDecisionPolicyRef  = "helm.decision.policy_ref"
	AttrDecisionLatencyMs  = "helm.decision.latency_ms"

	// Effect attributes
	AttrEffectType     = "helm.effect.type"
	AttrEffectRiskTier = "helm.effect.risk_tier"
	AttrEffectToolName = "helm.effect.tool_name"

	// Budget attributes
	AttrBudgetConsumed  = "helm.budget.consumed"
	AttrBudgetRemaining = "helm.budget.remaining"
	AttrBudgetCeiling   = "helm.budget.ceiling"

	// Receipt attributes
	AttrReceiptHash       = "helm.receipt.hash"
	AttrProofGraphLamport = "helm.proofgraph.lamport"

	// A2A attributes
	AttrA2AOriginAgent       = "helm.a2a.origin_agent"
	AttrA2ATargetAgent       = "helm.a2a.target_agent"
	AttrA2ANegotiationResult = "helm.a2a.negotiation_result"
)

// Config holds configuration for the governance telemetry exporter.
type Config struct {
	ServiceName string
	Endpoint    string // OTLP gRPC endpoint (e.g., "localhost:4317")
	Insecure    bool   // Use insecure connection (for local dev)
}

// GovernanceTracer exports governance telemetry as OpenTelemetry data.
type GovernanceTracer struct {
	tracer         trace.Tracer
	meter          metric.Meter
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider

	// Metrics
	decisionCounter metric.Int64Counter
	denialCounter   metric.Int64Counter
	budgetGauge     metric.Float64Gauge
	latencyHist     metric.Float64Histogram
}

// NewGovernanceTracer creates a new governance telemetry exporter.
// Returns a no-op tracer if endpoint is empty (graceful degradation).
func NewGovernanceTracer(cfg Config) (*GovernanceTracer, error) {
	ctx := context.Background()

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
			attribute.String("helm.component", "guardian"),
		),
	)
	if err != nil {
		return nil, err
	}

	gt := &GovernanceTracer{}

	// Set up trace exporter
	if cfg.Endpoint != "" {
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}

		exporter, err := otlptracegrpc.New(ctx, opts...)
		if err != nil {
			return nil, err
		}

		gt.tracerProvider = sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(res),
		)
		otel.SetTracerProvider(gt.tracerProvider)
	}

	gt.tracer = otel.Tracer("helm.governance")

	// Set up meter
	gt.meterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
	)
	gt.meter = gt.meterProvider.Meter("helm.governance")

	// Register metrics
	gt.decisionCounter, _ = gt.meter.Int64Counter("helm.decisions.total",
		metric.WithDescription("Total governance decisions"),
	)
	gt.denialCounter, _ = gt.meter.Int64Counter("helm.denials.total",
		metric.WithDescription("Total governance denials"),
	)
	gt.budgetGauge, _ = gt.meter.Float64Gauge("helm.budget.utilization",
		metric.WithDescription("Budget utilization ratio"),
	)
	gt.latencyHist, _ = gt.meter.Float64Histogram("helm.decision.latency",
		metric.WithDescription("Governance decision latency in milliseconds"),
		metric.WithUnit("ms"),
	)

	return gt, nil
}

// Shutdown flushes and shuts down the telemetry pipeline.
func (gt *GovernanceTracer) Shutdown(ctx context.Context) error {
	if gt.tracerProvider != nil {
		if err := gt.tracerProvider.Shutdown(ctx); err != nil {
			return err
		}
	}
	if gt.meterProvider != nil {
		return gt.meterProvider.Shutdown(ctx)
	}
	return nil
}

// DecisionEvent represents a governance decision to trace.
//
// All "GenAI" fields are optional; when populated the resulting span carries
// the OTel GenAI semconv attributes alongside the existing helm.* keys, so a
// single trace describes both the model invocation and the governance verdict.
type DecisionEvent struct {
	Verdict    string
	ReasonCode string
	PolicyRef  string
	EffectType string
	RiskTier   string
	ToolName   string
	LatencyMs  float64
	Lamport    uint64

	// GenAI semconv fields (optional). See core/pkg/observability/genai_attrs.go.
	GenAISystem        string // e.g. "openai", "anthropic", "aws.bedrock"
	GenAIRequestModel  string // e.g. "gpt-4o", "claude-3-5-sonnet"
	GenAIOperationName string // e.g. "chat", "tool_call"
	GenAIToolCallID    string // upstream tool_call id; mirrors helm correlation_id
	GenAIInputTokens   int64
	GenAIOutputTokens  int64
	GenAIFinishReason  string
	GenAIResponseModel string
	GenAIResponseID    string

	// helm-specific governance attributes.
	HelmPolicyID      string // typically equal to PolicyRef
	HelmProofNodeID   string
	HelmCorrelationID string
	HelmReceiptID     string
	HelmTenantID      string
}

// TraceDecision records a governance decision as an OTel span and metric.
//
// The span carries both the legacy helm.decision.* attributes (kept for
// dashboard back-compat) and the OTel GenAI semconv keys (gen_ai.*) when
// the corresponding fields on the event are populated. helm-specific
// governance attributes (helm.verdict, helm.policy_id, helm.proof_node_id)
// always live under the helm.* namespace so they cannot collide with
// upstream GenAI semantic conventions.
func (gt *GovernanceTracer) TraceDecision(ctx context.Context, d DecisionEvent) {
	attrs := []attribute.KeyValue{
		// Legacy helm.decision.* attributes (kept for back-compat).
		attribute.String(AttrDecisionVerdict, d.Verdict),
		attribute.String(AttrDecisionReasonCode, d.ReasonCode),
		attribute.String(AttrDecisionPolicyRef, d.PolicyRef),
		attribute.String(AttrEffectType, d.EffectType),
		attribute.String(AttrEffectRiskTier, d.RiskTier),
		attribute.String(AttrEffectToolName, d.ToolName),
		attribute.Float64(AttrDecisionLatencyMs, d.LatencyMs),
		attribute.Int64(AttrProofGraphLamport, int64(d.Lamport)),

		// helm.* governance namespace (single source of truth in observability).
		attribute.String(observability.HelmVerdict, d.Verdict),
		attribute.String(observability.HelmReasonCode, d.ReasonCode),
		attribute.Int64(observability.HelmLamport, int64(d.Lamport)),
	}
	policyID := d.HelmPolicyID
	if policyID == "" {
		policyID = d.PolicyRef
	}
	if policyID != "" {
		attrs = append(attrs, attribute.String(observability.HelmPolicyID, policyID))
	}
	if d.HelmProofNodeID != "" {
		attrs = append(attrs, attribute.String(observability.HelmProofNodeID, d.HelmProofNodeID))
	}
	if d.HelmCorrelationID != "" {
		attrs = append(attrs, attribute.String(observability.HelmCorrelationID, d.HelmCorrelationID))
	}
	if d.HelmReceiptID != "" {
		attrs = append(attrs, attribute.String(observability.HelmReceiptID, d.HelmReceiptID))
	}
	if d.HelmTenantID != "" {
		attrs = append(attrs, attribute.String(observability.HelmTenantID, d.HelmTenantID))
	}

	// OTel GenAI semconv keys (only emitted when populated).
	if d.GenAISystem != "" {
		attrs = append(attrs, attribute.String(observability.GenAISystem, d.GenAISystem))
	}
	if d.GenAIRequestModel != "" {
		attrs = append(attrs, attribute.String(observability.GenAIRequestModel, d.GenAIRequestModel))
	}
	if d.GenAIOperationName != "" {
		attrs = append(attrs, attribute.String(observability.GenAIOperationName, d.GenAIOperationName))
	}
	if d.ToolName != "" {
		attrs = append(attrs, attribute.String(observability.GenAIToolName, d.ToolName))
	}
	if d.GenAIToolCallID != "" {
		attrs = append(attrs, attribute.String(observability.GenAIToolCallID, d.GenAIToolCallID))
	}
	if d.GenAIInputTokens > 0 {
		attrs = append(attrs, attribute.Int64(observability.GenAIUsageInputTokens, d.GenAIInputTokens))
	}
	if d.GenAIOutputTokens > 0 {
		attrs = append(attrs, attribute.Int64(observability.GenAIUsageOutputTokens, d.GenAIOutputTokens))
	}
	if d.GenAIFinishReason != "" {
		attrs = append(attrs, attribute.String(observability.GenAIResponseFinishReason, d.GenAIFinishReason))
	}
	if d.GenAIResponseModel != "" {
		attrs = append(attrs, attribute.String(observability.GenAIResponseModel, d.GenAIResponseModel))
	}
	if d.GenAIResponseID != "" {
		attrs = append(attrs, attribute.String(observability.GenAIResponseID, d.GenAIResponseID))
	}

	_, span := gt.tracer.Start(ctx, "helm.governance.decision",
		trace.WithAttributes(attrs...),
	)
	span.End()

	mAttrs := metric.WithAttributes(
		attribute.String(AttrDecisionVerdict, d.Verdict),
		attribute.String(AttrEffectType, d.EffectType),
	)
	gt.decisionCounter.Add(ctx, 1, mAttrs)
	gt.latencyHist.Record(ctx, d.LatencyMs, mAttrs)
}

// GenAIToolCallEvent represents a single governed model tool-call invocation,
// emitted as an OTel span carrying the full GenAI semconv attribute set
// alongside helm.* governance attributes.
type GenAIToolCallEvent struct {
	System        string // GenAI system: "openai", "anthropic", "aws.bedrock"
	RequestModel  string
	ResponseModel string
	ResponseID    string
	OperationName string // "chat" | "tool_call" | …
	ToolName      string
	ToolCallID    string // mirrors helm correlation_id
	InputTokens   int64
	OutputTokens  int64
	FinishReason  string

	// helm.* governance fields.
	Verdict       string
	ReasonCode    string
	PolicyID      string
	ProofNodeID   string
	CorrelationID string
	ReceiptID     string
	TenantID      string
	LatencyMs     float64
}

// TraceGenAIToolCall records a single GenAI tool-call invocation as an OTel
// span. The span name is "gen_ai.tool_call" so OTel collectors can filter
// GenAI traffic distinctly from internal governance spans.
func (gt *GovernanceTracer) TraceGenAIToolCall(ctx context.Context, e GenAIToolCallEvent) trace.SpanContext {
	attrs := []attribute.KeyValue{}
	if e.System != "" {
		attrs = append(attrs, attribute.String(observability.GenAISystem, e.System))
	}
	if e.RequestModel != "" {
		attrs = append(attrs, attribute.String(observability.GenAIRequestModel, e.RequestModel))
	}
	if e.ResponseModel != "" {
		attrs = append(attrs, attribute.String(observability.GenAIResponseModel, e.ResponseModel))
	}
	if e.ResponseID != "" {
		attrs = append(attrs, attribute.String(observability.GenAIResponseID, e.ResponseID))
	}
	if e.OperationName != "" {
		attrs = append(attrs, attribute.String(observability.GenAIOperationName, e.OperationName))
	}
	if e.ToolName != "" {
		attrs = append(attrs, attribute.String(observability.GenAIToolName, e.ToolName))
	}
	if e.ToolCallID != "" {
		attrs = append(attrs, attribute.String(observability.GenAIToolCallID, e.ToolCallID))
	}
	if e.InputTokens > 0 {
		attrs = append(attrs, attribute.Int64(observability.GenAIUsageInputTokens, e.InputTokens))
	}
	if e.OutputTokens > 0 {
		attrs = append(attrs, attribute.Int64(observability.GenAIUsageOutputTokens, e.OutputTokens))
	}
	if e.FinishReason != "" {
		attrs = append(attrs, attribute.String(observability.GenAIResponseFinishReason, e.FinishReason))
	}
	if e.Verdict != "" {
		attrs = append(attrs, attribute.String(observability.HelmVerdict, e.Verdict))
	}
	if e.ReasonCode != "" {
		attrs = append(attrs, attribute.String(observability.HelmReasonCode, e.ReasonCode))
	}
	if e.PolicyID != "" {
		attrs = append(attrs, attribute.String(observability.HelmPolicyID, e.PolicyID))
	}
	if e.ProofNodeID != "" {
		attrs = append(attrs, attribute.String(observability.HelmProofNodeID, e.ProofNodeID))
	}
	if e.CorrelationID != "" {
		attrs = append(attrs, attribute.String(observability.HelmCorrelationID, e.CorrelationID))
	}
	if e.ReceiptID != "" {
		attrs = append(attrs, attribute.String(observability.HelmReceiptID, e.ReceiptID))
	}
	if e.TenantID != "" {
		attrs = append(attrs, attribute.String(observability.HelmTenantID, e.TenantID))
	}
	if e.LatencyMs > 0 {
		attrs = append(attrs, attribute.Float64(AttrDecisionLatencyMs, e.LatencyMs))
	}

	_, span := gt.tracer.Start(ctx, "gen_ai.tool_call", trace.WithAttributes(attrs...))
	sc := span.SpanContext()
	span.End()
	return sc
}

// DenialEvent represents a governance denial to trace.
type DenialEvent struct {
	ReasonCode string
	PolicyRef  string
	EffectType string
	ToolName   string
	Details    string

	// Optional GenAI semconv fields. When populated, the denial span carries
	// gen_ai.* attributes so SIEM/OTel backends can join denials to their
	// upstream model invocations.
	GenAISystem        string
	GenAIRequestModel  string
	GenAIOperationName string
	GenAIToolCallID    string

	// helm.* governance attributes.
	HelmPolicyID      string
	HelmProofNodeID   string
	HelmCorrelationID string
	HelmTenantID      string
}

// TraceDenial records a denial as an OTel span and metric.
func (gt *GovernanceTracer) TraceDenial(ctx context.Context, d DenialEvent) {
	attrs := []attribute.KeyValue{
		// Legacy keys.
		attribute.String(AttrDecisionVerdict, "DENY"),
		attribute.String(AttrDecisionReasonCode, d.ReasonCode),
		attribute.String(AttrDecisionPolicyRef, d.PolicyRef),
		attribute.String(AttrEffectType, d.EffectType),
		attribute.String(AttrEffectToolName, d.ToolName),

		// helm.* namespace.
		attribute.String(observability.HelmVerdict, "DENY"),
		attribute.String(observability.HelmReasonCode, d.ReasonCode),
	}
	policyID := d.HelmPolicyID
	if policyID == "" {
		policyID = d.PolicyRef
	}
	if policyID != "" {
		attrs = append(attrs, attribute.String(observability.HelmPolicyID, policyID))
	}
	if d.HelmProofNodeID != "" {
		attrs = append(attrs, attribute.String(observability.HelmProofNodeID, d.HelmProofNodeID))
	}
	if d.HelmCorrelationID != "" {
		attrs = append(attrs, attribute.String(observability.HelmCorrelationID, d.HelmCorrelationID))
	}
	if d.HelmTenantID != "" {
		attrs = append(attrs, attribute.String(observability.HelmTenantID, d.HelmTenantID))
	}
	if d.GenAISystem != "" {
		attrs = append(attrs, attribute.String(observability.GenAISystem, d.GenAISystem))
	}
	if d.GenAIRequestModel != "" {
		attrs = append(attrs, attribute.String(observability.GenAIRequestModel, d.GenAIRequestModel))
	}
	if d.GenAIOperationName != "" {
		attrs = append(attrs, attribute.String(observability.GenAIOperationName, d.GenAIOperationName))
	}
	if d.ToolName != "" {
		attrs = append(attrs, attribute.String(observability.GenAIToolName, d.ToolName))
	}
	if d.GenAIToolCallID != "" {
		attrs = append(attrs, attribute.String(observability.GenAIToolCallID, d.GenAIToolCallID))
	}

	_, span := gt.tracer.Start(ctx, "helm.governance.denial",
		trace.WithAttributes(attrs...),
	)
	if d.Details != "" {
		span.AddEvent("denial_details", trace.WithAttributes(
			attribute.String("details", d.Details),
		))
	}
	span.End()

	gt.denialCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String(AttrDecisionReasonCode, d.ReasonCode),
		attribute.String(AttrEffectType, d.EffectType),
	))
}

// InjectTraceparent writes the active span context from ctx into the outgoing
// HTTP headers as a W3C traceparent. Use this before forwarding a request to
// an upstream model provider so the downstream span tree links back to the
// helm governance span.
func InjectTraceparent(ctx context.Context, headers http.Header) {
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(headers))
}

// ExtractTraceparent reads the W3C traceparent header on incoming HTTP and
// returns a context carrying the upstream span context.
func ExtractTraceparent(ctx context.Context, headers http.Header) context.Context {
	return propagation.TraceContext{}.Extract(ctx, propagation.HeaderCarrier(headers))
}

// BudgetEvent represents a budget state update to trace.
type BudgetEvent struct {
	Consumed  float64
	Remaining float64
	Ceiling   float64
}

// TraceBudget records the current budget state as an OTel metric.
func (gt *GovernanceTracer) TraceBudget(ctx context.Context, b BudgetEvent) {
	if b.Ceiling > 0 {
		gt.budgetGauge.Record(ctx, b.Consumed/b.Ceiling)
	}
}

// ── No-op Tracer ─────────────────────────────────────────────

// NoopTracer returns a tracer that does nothing (for when OTel is disabled).
func NoopTracer() *GovernanceTracer {
	meter := sdkmetric.NewMeterProvider().Meter("helm.governance.noop")
	counter, _ := meter.Int64Counter("helm.decisions.total")
	denials, _ := meter.Int64Counter("helm.denials.total")
	gauge, _ := meter.Float64Gauge("helm.budget.utilization")
	hist, _ := meter.Float64Histogram("helm.decision.latency")
	return &GovernanceTracer{
		tracer:          otel.Tracer("helm.governance.noop"),
		meter:           meter,
		decisionCounter: counter,
		denialCounter:   denials,
		budgetGauge:     gauge,
		latencyHist:     hist,
	}
}

// MeasureDecision is a convenience wrapper that measures the duration of a
// governance decision and traces it automatically.
func (gt *GovernanceTracer) MeasureDecision(ctx context.Context, verdict, reasonCode, policyRef, effectType, toolName string) func() {
	start := time.Now()
	return func() {
		gt.TraceDecision(ctx, DecisionEvent{
			Verdict:    verdict,
			ReasonCode: reasonCode,
			PolicyRef:  policyRef,
			EffectType: effectType,
			ToolName:   toolName,
			LatencyMs:  float64(time.Since(start).Microseconds()) / 1000.0,
		})
	}
}
