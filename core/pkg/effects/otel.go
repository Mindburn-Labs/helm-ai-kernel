// otel.go provides OpenTelemetry instrumentation for the effects gateway.
// It records traces for effect execution, permit validation, and connector
// calls, plus metrics for throughput, latency, and validation overhead.
//
// Usage: create with NewEffectsOTelInstrumentation() and pass to your
// Gateway implementation. All methods are nil-safe — a nil receiver is
// treated as "OTel disabled" with zero overhead.
//
// Design invariants:
//   - OTel is optional — the gateway works without it
//   - Zero allocation on hot path when OTel is disabled
//   - Traces include sub-spans for permit validation and connector calls
//   - Metrics use HELM namespace: "helm.effects.*"
//   - No sensitive data (params, outputs) in traces
package effects

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// ── Attribute key constants ─────────────────────────────────────

const (
	attrEffectType   = "effect_type"
	attrConnectorID  = "connector_id"
	attrSuccess      = "success"
)

// ── EffectsOTelInstrumentation ──────────────────────────────────

// EffectsOTelInstrumentation holds the tracer, meter, and pre-registered
// metric instruments for the effects gateway. When nil (the default),
// every method is a no-op so callers never need nil-checks.
type EffectsOTelInstrumentation struct {
	tracer trace.Tracer
	meter  metric.Meter

	// Counters
	executionsTotal metric.Int64Counter

	// Histograms
	executionDuration        metric.Float64Histogram
	permitValidationDuration metric.Float64Histogram
}

// NewEffectsOTelInstrumentation creates an EffectsOTelInstrumentation using
// the global TracerProvider and MeterProvider. Returns an error only if
// metric registration fails.
func NewEffectsOTelInstrumentation() (*EffectsOTelInstrumentation, error) {
	o := &EffectsOTelInstrumentation{
		tracer: otel.Tracer("helm.effects"),
		meter:  otel.Meter("helm.effects"),
	}

	var err error

	o.executionsTotal, err = o.meter.Int64Counter(
		"helm.effects.executions_total",
		metric.WithDescription("Total effect executions"),
		metric.WithUnit("{execution}"),
	)
	if err != nil {
		return nil, err
	}

	o.executionDuration, err = o.meter.Float64Histogram(
		"helm.effects.execution_duration_ms",
		metric.WithDescription("Effect execution latency in milliseconds"),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(0.1, 0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000),
	)
	if err != nil {
		return nil, err
	}

	o.permitValidationDuration, err = o.meter.Float64Histogram(
		"helm.effects.permit_validation_duration_ms",
		metric.WithDescription("Permit validation latency in milliseconds"),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5),
	)
	if err != nil {
		return nil, err
	}

	return o, nil
}

// ── Span helpers ────────────────────────────────────────────────

// StartExecution begins the root span for an effect execution.
// The returned span MUST be ended by the caller (defer span.End()).
func (o *EffectsOTelInstrumentation) StartExecution(ctx context.Context, effectType EffectType, connectorID string) (context.Context, trace.Span) {
	if o == nil {
		return ctx, noopSpan()
	}
	ctx, span := o.tracer.Start(ctx, "effects.execute",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String(attrEffectType, string(effectType)),
			attribute.String(attrConnectorID, connectorID),
		),
	)
	return ctx, span
}

// StartPermitValidation begins a child span for permit validation.
func (o *EffectsOTelInstrumentation) StartPermitValidation(ctx context.Context) (context.Context, trace.Span) {
	if o == nil {
		return ctx, noopSpan()
	}
	return o.tracer.Start(ctx, "effects.permit_validate",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
}

// StartConnectorCall begins a child span for the actual connector execution.
func (o *EffectsOTelInstrumentation) StartConnectorCall(ctx context.Context, connectorID string) (context.Context, trace.Span) {
	if o == nil {
		return ctx, noopSpan()
	}
	return o.tracer.Start(ctx, "effects.connector_call",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String(attrConnectorID, connectorID),
		),
	)
}

// EndSpan finalizes a span. Convenience wrapper for consistency.
func (o *EffectsOTelInstrumentation) EndSpan(span trace.Span) {
	if o == nil {
		return
	}
	span.End()
}

// MarkSuccess records whether the execution succeeded on a span.
func (o *EffectsOTelInstrumentation) MarkSuccess(span trace.Span, success bool) {
	if o == nil {
		return
	}
	span.SetAttributes(attribute.Bool(attrSuccess, success))
}

// ── Metric helpers ──────────────────────────────────────────────

// RecordExecution increments the executions counter and records duration.
// Safe to call when o is nil.
func (o *EffectsOTelInstrumentation) RecordExecution(ctx context.Context, effectType EffectType, connectorID string, success bool, duration time.Duration) {
	if o == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String(attrEffectType, string(effectType)),
		attribute.String(attrConnectorID, connectorID),
		attribute.Bool(attrSuccess, success),
	)
	o.executionsTotal.Add(ctx, 1, attrs)
	o.executionDuration.Record(ctx, float64(duration.Microseconds())/1000.0, attrs)
}

// RecordPermitValidation records the permit validation duration.
func (o *EffectsOTelInstrumentation) RecordPermitValidation(ctx context.Context, duration time.Duration) {
	if o == nil {
		return
	}
	o.permitValidationDuration.Record(ctx, float64(duration.Microseconds())/1000.0)
}

// ── noop helpers ────────────────────────────────────────────────

// noopSpan returns a span that silently discards all operations.
func noopSpan() trace.Span {
	return trace.SpanFromContext(context.Background())
}
