package tracing

import (
	"context"
	"fmt"
	"time"

	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// otelConfig holds configuration for OTelTracer.
type otelConfig struct {
	endpoint   string  // OTLP gRPC endpoint, e.g. "localhost:4317"
	sampleRate float64 // 0.0–1.0; default 1.0
	insecure   bool    // use insecure connection (dev only)
}

// OTelOption is a functional option for NewOTelTracer.
type OTelOption func(*otelConfig)

// WithOTLPEndpoint sets the OTLP gRPC endpoint for trace export.
// When omitted, spans are produced but not exported externally.
func WithOTLPEndpoint(endpoint string) OTelOption {
	return func(c *otelConfig) {
		c.endpoint = endpoint
	}
}

// WithSampleRate sets the fraction of traces to sample (0.0–1.0).
// Values ≥ 1.0 sample everything; values ≤ 0.0 sample nothing.
func WithSampleRate(rate float64) OTelOption {
	return func(c *otelConfig) {
		c.sampleRate = rate
	}
}

// WithInsecure disables TLS on the OTLP connection (for local development).
func WithInsecure() OTelOption {
	return func(c *otelConfig) {
		c.insecure = true
	}
}

// OTelTracer implements Tracer backed by the OpenTelemetry SDK.
// It bridges the HELM Span type to OTel spans so exporters receive both.
type OTelTracer struct {
	otelTracer     oteltrace.Tracer
	tracerProvider *sdktrace.TracerProvider
	mu             sync.RWMutex
	exporters      []Exporter
	otelSpans      map[SpanID]oteltrace.Span // tracks live OTel spans for EndSpan
}

// NewOTelTracer creates a Tracer backed by OpenTelemetry.
//
//	tracer, err := tracing.NewOTelTracer("helm-guardian",
//	    tracing.WithOTLPEndpoint("localhost:4317"),
//	    tracing.WithSampleRate(1.0),
//	)
func NewOTelTracer(serviceName string, opts ...OTelOption) (*OTelTracer, error) {
	cfg := &otelConfig{sampleRate: 1.0}
	for _, o := range opts {
		o(cfg)
	}

	ctx := context.Background()

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			attribute.String("helm.component", "tracing"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: create resource: %w", err)
	}

	sampler := resolveSampler(cfg.sampleRate)

	var batcherOpts []otlptracegrpc.Option
	var tp *sdktrace.TracerProvider

	if cfg.endpoint != "" {
		batcherOpts = append(batcherOpts, otlptracegrpc.WithEndpoint(cfg.endpoint))
		if cfg.insecure {
			batcherOpts = append(batcherOpts, otlptracegrpc.WithInsecure())
		}

		exporter, exportErr := otlptracegrpc.New(ctx, batcherOpts...)
		if exportErr != nil {
			return nil, fmt.Errorf("tracing: create OTLP exporter: %w", exportErr)
		}

		tp = sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter,
				sdktrace.WithBatchTimeout(5*time.Second),
			),
			sdktrace.WithResource(res),
			sdktrace.WithSampler(sampler),
		)
	} else {
		// No OTLP endpoint — produce spans locally (useful for in-process export).
		tp = sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			sdktrace.WithSampler(sampler),
		)
	}

	otel.SetTracerProvider(tp)

	return &OTelTracer{
		otelTracer:     tp.Tracer("helm.tracing"),
		tracerProvider: tp,
		otelSpans:      make(map[SpanID]oteltrace.Span),
	}, nil
}

// AddExporter registers an additional Exporter (e.g. LangSmith, Langfuse).
// Exporters are called on each EndSpan. Thread-safe.
func (t *OTelTracer) AddExporter(e Exporter) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.exporters = append(t.exporters, e)
}

// Shutdown gracefully flushes and stops the underlying OTel provider.
func (t *OTelTracer) Shutdown(ctx context.Context) error {
	if t.tracerProvider != nil {
		return t.tracerProvider.Shutdown(ctx)
	}
	return nil
}

// StartSpan begins a new HELM span backed by an OTel span.
func (t *OTelTracer) StartSpan(ctx context.Context, name string) (context.Context, *Span) {
	_, parentID := resolveIDs(ctx)

	// Capture the parent span ID from the pre-Start context.
	preStartCtx := oteltrace.SpanFromContext(ctx).SpanContext()
	if preStartCtx.IsValid() && preStartCtx.SpanID().IsValid() {
		parentID = SpanID(preStartCtx.SpanID().String())
	}

	// Start the OTel span so the OTel ecosystem records it too.
	ctx, otelSpan := t.otelTracer.Start(ctx, name)

	// Use OTel's new span IDs for the child span.
	otelSpanCtx := otelSpan.SpanContext()
	traceID := TraceID(otelSpanCtx.TraceID().String())
	spanID := SpanID(otelSpanCtx.SpanID().String())

	s := &Span{
		TraceID:     traceID,
		SpanID:      spanID,
		ParentID:    parentID,
		Name:        name,
		StartTimeMs: nowMs(),
		Status:      StatusOK,
	}

	// Track OTel span for EndSpan.
	t.mu.Lock()
	t.otelSpans[spanID] = otelSpan
	t.mu.Unlock()

	ctx = contextWithSpan(ctx, s)

	return ctx, s
}

// EndSpan finalises the HELM span and its underlying OTel span.
func (t *OTelTracer) EndSpan(span *Span, err error) {
	if span == nil {
		return
	}
	span.EndTimeMs = nowMs()
	if err != nil {
		span.Status = StatusError
	} else {
		span.Status = StatusOK
	}

	// End the underlying OTel span so the SDK batcher can export it.
	t.mu.Lock()
	if otelSpan, ok := t.otelSpans[span.SpanID]; ok {
		otelSpan.End()
		delete(t.otelSpans, span.SpanID)
	}
	t.mu.Unlock()

	// Best-effort export to registered exporters.
	t.mu.RLock()
	hasExporters := len(t.exporters) > 0
	t.mu.RUnlock()
	if hasExporters {
		_ = t.Export(context.Background(), []Span{*span})
	}
}

// Export sends spans to all registered Exporters.
func (t *OTelTracer) Export(ctx context.Context, spans []Span) error {
	var firstErr error
	for _, e := range t.exporters {
		if err := e.Export(ctx, spans); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// otelSpanKey stores the live OTel span in the context so EndSpan can close it.
type otelSpanKey struct{}

// resolveSampler converts a sample rate to an OTel Sampler.
func resolveSampler(rate float64) sdktrace.Sampler {
	switch {
	case rate >= 1.0:
		return sdktrace.AlwaysSample()
	case rate <= 0.0:
		return sdktrace.NeverSample()
	default:
		return sdktrace.TraceIDRatioBased(rate)
	}
}
