// Package observability provides OpenTelemetry-based observability for HELM.
//
// This package implements:
// - Distributed tracing with OTLP export
// - Metrics collection with RED (Rate, Errors, Duration) pattern
// - Semantic conventions per OpenTelemetry specification
// - Zero-code auto-instrumentation hooks for critical paths
package observability

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config configures the OpenTelemetry providers.
type Config struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	OTLPEndpoint   string        // e.g., "localhost:4317" for gRPC
	SampleRate     float64       // 0.0 to 1.0, default 1.0 (sample all)
	BatchTimeout   time.Duration // How long to wait before sending batched spans
	Enabled        bool          // Enable/disable telemetry
	Insecure       bool          // Use insecure connection (dev only)
	CertFile       string        // Path to client certificate
	KeyFile        string        // Path to client key
	CAFile         string        // Path to CA certificate
}

// DefaultConfig returns production-ready defaults.
func DefaultConfig() *Config {
	return &Config{
		ServiceName:    "helm-sovereign-os",
		ServiceVersion: "2.0.0",
		Environment:    "development",
		OTLPEndpoint:   "localhost:4317",
		SampleRate:     1.0, // Sample everything in dev
		BatchTimeout:   5 * time.Second,
		Enabled:        true,
		Insecure:       false, // Secure by default
	}
}

// Provider manages OpenTelemetry trace and metric providers.
type Provider struct {
	config         *Config
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	tracer         trace.Tracer
	meter          metric.Meter
	logger         *slog.Logger

	// RED metrics (Rate, Errors, Duration)
	requestCounter   metric.Int64Counter
	errorCounter     metric.Int64Counter
	durationHist     metric.Float64Histogram
	activeOperations metric.Int64UpDownCounter
}

// New creates a new observability provider.
func New(ctx context.Context, config *Config) (*Provider, error) {
	if config == nil {
		config = DefaultConfig()
	}

	p := &Provider{
		config: config,
		logger: slog.Default().With("component", "observability"),
	}

	if !config.Enabled {
		p.logger.InfoContext(ctx, "observability disabled")
		return p, nil
	}

	// Create resource with service information
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion(config.ServiceVersion),
			semconv.DeploymentEnvironment(config.Environment),
			attribute.String("helm.component", "core"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Initialize trace provider
	if err := p.initTraceProvider(ctx, res); err != nil {
		return nil, fmt.Errorf("failed to init trace provider: %w", err)
	}

	// Initialize metric provider
	if err := p.initMetricProvider(ctx, res); err != nil {
		return nil, fmt.Errorf("failed to init metric provider: %w", err)
	}

	// Create tracer and meter for HELM
	p.tracer = otel.Tracer("helm.sovereign-os",
		trace.WithInstrumentationVersion(config.ServiceVersion),
	)
	p.meter = otel.Meter("helm.sovereign-os",
		metric.WithInstrumentationVersion(config.ServiceVersion),
	)

	// Initialize RED metrics
	if err := p.initREDMetrics(); err != nil {
		return nil, fmt.Errorf("failed to init RED metrics: %w", err)
	}

	p.logger.InfoContext(ctx, "observability initialized",
		"service", config.ServiceName,
		"environment", config.Environment,
		"endpoint", config.OTLPEndpoint,
		"sample_rate", config.SampleRate,
		"insecure", config.Insecure,
	)

	return p, nil
}

// initTraceProvider initializes the OpenTelemetry trace provider.
func (p *Provider) initTraceProvider(ctx context.Context, res *resource.Resource) error {
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(p.config.OTLPEndpoint),
	}

	if p.config.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	} else {
		if p.config.CertFile != "" || p.config.KeyFile != "" || p.config.CAFile != "" {
			p.logger.InfoContext(ctx, "TLS credential paths configured for OTLP exporter",
				"cert", p.config.CertFile, "key", p.config.KeyFile, "ca", p.config.CAFile)
		}
	}

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Configure sampler based on sample rate
	var sampler sdktrace.Sampler
	if p.config.SampleRate >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if p.config.SampleRate <= 0.0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(p.config.SampleRate)
	}

	p.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(p.config.BatchTimeout),
		),
		sdktrace.WithSampler(sampler),
	)

	// Set as global provider
	otel.SetTracerProvider(p.tracerProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return nil
}

// initMetricProvider initializes the OpenTelemetry metric provider.
func (p *Provider) initMetricProvider(ctx context.Context, res *resource.Resource) error {
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(p.config.OTLPEndpoint),
	}

	if p.config.Insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}

	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create metric exporter: %w", err)
	}

	p.meterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter,
			sdkmetric.WithInterval(15*time.Second),
		)),
	)

	// Set as global provider
	otel.SetMeterProvider(p.meterProvider)

	return nil
}

// initREDMetrics initializes Rate, Errors, Duration metrics.
func (p *Provider) initREDMetrics() error {
	var err error

	// Rate - Request counter
	p.requestCounter, err = p.meter.Int64Counter("helm.requests.total",
		metric.WithDescription("Total number of requests processed"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return err
	}

	// Errors - Error counter
	p.errorCounter, err = p.meter.Int64Counter("helm.errors.total",
		metric.WithDescription("Total number of errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return err
	}

	// Duration - Latency histogram
	p.durationHist, err = p.meter.Float64Histogram("helm.request.duration",
		metric.WithDescription("Request duration in seconds"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
	)
	if err != nil {
		return err
	}

	// Active operations gauge
	p.activeOperations, err = p.meter.Int64UpDownCounter("helm.operations.active",
		metric.WithDescription("Number of currently active operations"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return err
	}

	return nil
}

// Shutdown gracefully shuts down the providers.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.tracerProvider != nil {
		if err := p.tracerProvider.Shutdown(ctx); err != nil {
			p.logger.ErrorContext(ctx, "failed to shutdown trace provider", "error", err)
		}
	}
	if p.meterProvider != nil {
		if err := p.meterProvider.Shutdown(ctx); err != nil {
			p.logger.ErrorContext(ctx, "failed to shutdown metric provider", "error", err)
		}
	}
	return nil
}

// Tracer returns the configured tracer.
func (p *Provider) Tracer() trace.Tracer {
	if p.tracer == nil {
		return otel.Tracer("helm.sovereign-os")
	}
	return p.tracer
}

// Meter returns the configured meter.
func (p *Provider) Meter() metric.Meter {
	if p.meter == nil {
		return otel.Meter("helm.sovereign-os")
	}
	return p.meter
}

// StartSpan starts a new span with the given name.
func (p *Provider) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return p.Tracer().Start(ctx, name, opts...)
}

// RecordRequest records a request with the given attributes.
func (p *Provider) RecordRequest(ctx context.Context, attrs ...attribute.KeyValue) {
	if p.requestCounter != nil {
		p.requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// RecordError records an error with the given attributes.
func (p *Provider) RecordError(ctx context.Context, err error, attrs ...attribute.KeyValue) {
	if p.errorCounter != nil {
		allAttrs := append(attrs, attribute.String("error.type", fmt.Sprintf("%T", err)))
		p.errorCounter.Add(ctx, 1, metric.WithAttributes(allAttrs...))
	}
}

// RecordDuration records the duration of an operation.
func (p *Provider) RecordDuration(ctx context.Context, duration time.Duration, attrs ...attribute.KeyValue) {
	if p.durationHist != nil {
		p.durationHist.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
	}
}

// TrackOperation tracks an operation from start to finish.
// Returns a function that should be called when the operation completes.
func (p *Provider) TrackOperation(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, func(error)) {
	start := time.Now()

	// Start span
	ctx, span := p.StartSpan(ctx, name,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)

	// Increment active operations
	if p.activeOperations != nil {
		p.activeOperations.Add(ctx, 1, metric.WithAttributes(attrs...))
	}

	// Record request
	p.RecordRequest(ctx, attrs...)

	return ctx, func(err error) {
		duration := time.Since(start)

		// Decrement active operations
		if p.activeOperations != nil {
			p.activeOperations.Add(ctx, -1, metric.WithAttributes(attrs...))
		}

		// Record duration
		p.RecordDuration(ctx, duration, attrs...)

		// Handle error
		if err != nil {
			span.RecordError(err)
			p.RecordError(ctx, err, attrs...)
		}

		span.End()
	}
}
