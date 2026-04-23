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
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
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
type DecisionEvent struct {
	Verdict    string
	ReasonCode string
	PolicyRef  string
	EffectType string
	RiskTier   string
	ToolName   string
	LatencyMs  float64
	Lamport    uint64
}

// TraceDecision records a governance decision as an OTel span and metric.
func (gt *GovernanceTracer) TraceDecision(ctx context.Context, d DecisionEvent) {
	_, span := gt.tracer.Start(ctx, "helm.governance.decision",
		trace.WithAttributes(
			attribute.String(AttrDecisionVerdict, d.Verdict),
			attribute.String(AttrDecisionReasonCode, d.ReasonCode),
			attribute.String(AttrDecisionPolicyRef, d.PolicyRef),
			attribute.String(AttrEffectType, d.EffectType),
			attribute.String(AttrEffectRiskTier, d.RiskTier),
			attribute.String(AttrEffectToolName, d.ToolName),
			attribute.Float64(AttrDecisionLatencyMs, d.LatencyMs),
			attribute.Int64(AttrProofGraphLamport, int64(d.Lamport)),
		),
	)
	span.End()

	attrs := metric.WithAttributes(
		attribute.String(AttrDecisionVerdict, d.Verdict),
		attribute.String(AttrEffectType, d.EffectType),
	)
	gt.decisionCounter.Add(ctx, 1, attrs)
	gt.latencyHist.Record(ctx, d.LatencyMs, attrs)
}

// DenialEvent represents a governance denial to trace.
type DenialEvent struct {
	ReasonCode string
	PolicyRef  string
	EffectType string
	ToolName   string
	Details    string
}

// TraceDenial records a denial as an OTel span and metric.
func (gt *GovernanceTracer) TraceDenial(ctx context.Context, d DenialEvent) {
	_, span := gt.tracer.Start(ctx, "helm.governance.denial",
		trace.WithAttributes(
			attribute.String(AttrDecisionVerdict, "DENY"),
			attribute.String(AttrDecisionReasonCode, d.ReasonCode),
			attribute.String(AttrDecisionPolicyRef, d.PolicyRef),
			attribute.String(AttrEffectType, d.EffectType),
			attribute.String(AttrEffectToolName, d.ToolName),
		),
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
