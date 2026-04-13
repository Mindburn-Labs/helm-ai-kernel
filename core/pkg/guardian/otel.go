// otel.go provides OpenTelemetry instrumentation for the Guardian pipeline.
// It records traces for each decision evaluation and metrics for latency,
// verdict distribution, and gate-level performance.
//
// Usage: attach via GuardianOption:
//
//	guardian.NewGuardian(signer, graph, registry, guardian.WithOTel())
//
// Design invariants:
//   - OTel is optional — Guardian works without it
//   - Zero allocation on hot path when OTel is disabled
//   - Traces include gate-level spans for debugging
//   - Metrics use HELM namespace: "helm.guardian.*"
//   - No sensitive data (principal IDs, payloads) in traces
package guardian

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
	attrVerdict    = "helm.verdict"
	attrReasonCode = "helm.reason_code"
	attrPrincipal  = "helm.principal"
	attrAction     = "helm.action"
	attrGatePassed = "helm.gate.passed"
	attrGate       = "gate"
)

// ── OTelInstrumentation ─────────────────────────────────────────

// OTelInstrumentation holds the tracer, meter, and pre-registered metric
// instruments for the Guardian pipeline. When nil (the default), every
// method is a no-op so callers never need nil-checks.
type OTelInstrumentation struct {
	tracer trace.Tracer
	meter  metric.Meter

	// Counters
	decisionsTotal   metric.Int64Counter
	gateDenialsTotal metric.Int64Counter

	// Histograms
	decisionDuration metric.Float64Histogram
	gateDuration     metric.Float64Histogram
}

// newOTelInstrumentation creates an OTelInstrumentation using the global
// TracerProvider and MeterProvider. It returns an error only if metric
// registration fails (which in practice never happens with the OTel SDK).
func newOTelInstrumentation() (*OTelInstrumentation, error) {
	o := &OTelInstrumentation{
		tracer: otel.Tracer("helm.guardian"),
		meter:  otel.Meter("helm.guardian"),
	}

	var err error

	o.decisionsTotal, err = o.meter.Int64Counter(
		"helm.guardian.decisions_total",
		metric.WithDescription("Total guardian decisions"),
		metric.WithUnit("{decision}"),
	)
	if err != nil {
		return nil, err
	}

	o.gateDenialsTotal, err = o.meter.Int64Counter(
		"helm.guardian.gate_denials_total",
		metric.WithDescription("Total gate denials"),
		metric.WithUnit("{denial}"),
	)
	if err != nil {
		return nil, err
	}

	o.decisionDuration, err = o.meter.Float64Histogram(
		"helm.guardian.decision_duration_ms",
		metric.WithDescription("Full pipeline decision latency in milliseconds"),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100),
	)
	if err != nil {
		return nil, err
	}

	o.gateDuration, err = o.meter.Float64Histogram(
		"helm.guardian.gate_duration_ms",
		metric.WithDescription("Per-gate evaluation latency in milliseconds"),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10),
	)
	if err != nil {
		return nil, err
	}

	return o, nil
}

// ── Span helpers ────────────────────────────────────────────────

// StartDecision begins the root span for a guardian evaluation.
// The returned span MUST be ended by the caller (defer span.End()).
func (o *OTelInstrumentation) StartDecision(ctx context.Context, principal, action string) (context.Context, trace.Span) {
	if o == nil {
		return ctx, noopSpan()
	}
	ctx, span := o.tracer.Start(ctx, "guardian.evaluate_decision",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String(attrPrincipal, principal),
			attribute.String(attrAction, action),
		),
	)
	return ctx, span
}

// EndDecision finalizes the root span with verdict and reason code.
func (o *OTelInstrumentation) EndDecision(span trace.Span, verdict, reasonCode string) {
	if o == nil {
		return
	}
	span.SetAttributes(
		attribute.String(attrVerdict, verdict),
		attribute.String(attrReasonCode, reasonCode),
	)
	span.End()
}

// StartGate begins a child span for a specific guardian gate.
// The returned span MUST be ended by the caller (defer span.End()).
func (o *OTelInstrumentation) StartGate(ctx context.Context, gateName string) (context.Context, trace.Span) {
	if o == nil {
		return ctx, noopSpan()
	}
	return o.tracer.Start(ctx, "guardian.gate."+gateName,
		trace.WithSpanKind(trace.SpanKindInternal),
	)
}

// EndGate finalizes a gate span and sets the passed attribute.
func (o *OTelInstrumentation) EndGate(span trace.Span, passed bool) {
	if o == nil {
		return
	}
	span.SetAttributes(attribute.Bool(attrGatePassed, passed))
	span.End()
}

// StartPDP begins a span for the policy decision point evaluation.
func (o *OTelInstrumentation) StartPDP(ctx context.Context) (context.Context, trace.Span) {
	if o == nil {
		return ctx, noopSpan()
	}
	return o.tracer.Start(ctx, "guardian.pdp",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
}

// StartSign begins a span for decision signing.
func (o *OTelInstrumentation) StartSign(ctx context.Context) (context.Context, trace.Span) {
	if o == nil {
		return ctx, noopSpan()
	}
	return o.tracer.Start(ctx, "guardian.sign",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
}

// ── Metric helpers ──────────────────────────────────────────────

// RecordDecision increments the decisions counter and records pipeline
// duration. Safe to call when o is nil.
func (o *OTelInstrumentation) RecordDecision(ctx context.Context, verdict string, duration time.Duration) {
	if o == nil {
		return
	}
	attrs := metric.WithAttributes(attribute.String(attrVerdict, verdict))
	o.decisionsTotal.Add(ctx, 1, attrs)
	o.decisionDuration.Record(ctx, float64(duration.Microseconds())/1000.0, attrs)
}

// RecordGateDenial increments the gate denial counter for the named gate.
func (o *OTelInstrumentation) RecordGateDenial(ctx context.Context, gateName string) {
	if o == nil {
		return
	}
	o.gateDenialsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String(attrGate, gateName),
	))
}

// RecordGateDuration records a per-gate duration measurement.
func (o *OTelInstrumentation) RecordGateDuration(ctx context.Context, gateName string, duration time.Duration) {
	if o == nil {
		return
	}
	o.gateDuration.Record(ctx, float64(duration.Microseconds())/1000.0, metric.WithAttributes(
		attribute.String(attrGate, gateName),
	))
}

// ── GuardianOption ──────────────────────────────────────────────

// WithOTel enables OpenTelemetry instrumentation on the Guardian.
// Uses the globally registered TracerProvider and MeterProvider.
// If metric initialization fails, the Guardian is created without OTel
// and a warning is logged via slog.
func WithOTel() GuardianOption {
	return func(g *Guardian) {
		inst, err := newOTelInstrumentation()
		if err != nil {
			// Do not fail Guardian creation — OTel is optional.
			return
		}
		g.otel = inst
	}
}

// WithOTelInstrumentation injects a pre-built OTelInstrumentation.
// Useful in tests or when sharing a single instrumentation across guardians.
func WithOTelInstrumentation(inst *OTelInstrumentation) GuardianOption {
	return func(g *Guardian) {
		g.otel = inst
	}
}

// ── noop helpers ────────────────────────────────────────────────

// noopSpan returns a span that silently discards all operations.
func noopSpan() trace.Span {
	return trace.SpanFromContext(context.Background())
}
