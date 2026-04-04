// Package tracing provides distributed tracing and observability primitives
// for HELM's AI execution firewall.
//
// It defines a Tracer interface with span lifecycle management and supports
// multiple export backends (OpenTelemetry, LangSmith, Langfuse). All spans
// carry a CorrelationID that flows across service boundaries via HTTP headers.
//
// Usage:
//
//	tracer, err := tracing.NewOTelTracer("helm-guardian",
//	    tracing.WithOTLPEndpoint("localhost:4317"),
//	    tracing.WithSampleRate(1.0),
//	)
//	if err != nil {
//	    // fall back to noop
//	    tracer = tracing.NewNoopTracer()
//	}
//
//	ctx, span := tracer.StartSpan(ctx, "policy.evaluate")
//	defer tracer.EndSpan(span, nil)
package tracing

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TraceID uniquely identifies a distributed trace.
type TraceID string

// SpanID uniquely identifies a span within a trace.
type SpanID string

// Span represents a unit of work within a trace.
type Span struct {
	TraceID     TraceID           `json:"trace_id"`
	SpanID      SpanID            `json:"span_id"`
	ParentID    SpanID            `json:"parent_id,omitempty"`
	Name        string            `json:"name"`
	StartTimeMs int64             `json:"start_time_ms"`
	EndTimeMs   int64             `json:"end_time_ms,omitempty"`
	Status      string            `json:"status"` // ok, error
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// StatusOK indicates the span completed without error.
const StatusOK = "ok"

// StatusError indicates the span completed with an error.
const StatusError = "error"

// Exporter exports completed spans to an observability backend.
type Exporter interface {
	Export(ctx context.Context, spans []Span) error
}

// Tracer creates and manages spans for distributed tracing.
type Tracer interface {
	// StartSpan begins a new span under the given context.
	// The returned context carries the span for downstream propagation.
	StartSpan(ctx context.Context, name string) (context.Context, *Span)

	// EndSpan finalises the span. Pass a non-nil err to mark it StatusError.
	EndSpan(span *Span, err error)

	// Export flushes completed spans to the configured backend(s).
	Export(ctx context.Context, spans []Span) error
}

// ── context key ──────────────────────────────────────────────────────────────

type spanContextKey struct{}

// contextWithSpan stores a span in the context.
func contextWithSpan(ctx context.Context, s *Span) context.Context {
	return context.WithValue(ctx, spanContextKey{}, s)
}

// SpanFromContext retrieves the active span from a context, if any.
func SpanFromContext(ctx context.Context) (*Span, bool) {
	s, ok := ctx.Value(spanContextKey{}).(*Span)
	return s, ok && s != nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// newSpanID generates a new random SpanID.
func newSpanID() SpanID {
	return SpanID(uuid.New().String())
}

// newTraceID generates a new random TraceID.
func newTraceID() TraceID {
	return TraceID(uuid.New().String())
}

// nowMs returns the current wall-clock time as Unix milliseconds.
func nowMs() int64 {
	return time.Now().UnixMilli()
}

// ── NoopTracer ────────────────────────────────────────────────────────────────

// NoopTracer is a Tracer that discards all spans.
// Use it when tracing is disabled to avoid nil-guard boilerplate.
type NoopTracer struct{}

// NewNoopTracer returns a Tracer that performs no operations.
func NewNoopTracer() Tracer {
	return &NoopTracer{}
}

// StartSpan returns a no-op span embedded in the context.
func (n *NoopTracer) StartSpan(ctx context.Context, name string) (context.Context, *Span) {
	traceID, parentID := resolveIDs(ctx)
	s := &Span{
		TraceID:     traceID,
		SpanID:      newSpanID(),
		ParentID:    parentID,
		Name:        name,
		StartTimeMs: nowMs(),
		Status:      StatusOK,
	}
	return contextWithSpan(ctx, s), s
}

// EndSpan records the end time and status on the span but does not export it.
func (n *NoopTracer) EndSpan(span *Span, err error) {
	if span == nil {
		return
	}
	span.EndTimeMs = nowMs()
	if err != nil {
		span.Status = StatusError
	} else {
		span.Status = StatusOK
	}
}

// Export is a no-op for the NoopTracer.
func (n *NoopTracer) Export(_ context.Context, _ []Span) error {
	return nil
}

// resolveIDs derives the trace ID and parent span ID from any active span in ctx.
func resolveIDs(ctx context.Context) (TraceID, SpanID) {
	if parent, ok := SpanFromContext(ctx); ok {
		return parent.TraceID, parent.SpanID
	}
	return newTraceID(), ""
}
