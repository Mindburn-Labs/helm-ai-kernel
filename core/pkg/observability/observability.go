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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
)

// Config configures the OpenTelemetry providers.
type Config struct {
	ServiceName     string
	ServiceVersion  string
	Environment     string
	OTLPEndpoint    string        // e.g., "localhost:4317" for gRPC
	MetricsExporter string        // "none" (default) or "otlp"
	SampleRate      float64       // 0.0 to 1.0, default 1.0 (sample all)
	BatchTimeout    time.Duration // How long to wait before sending batched spans
	Enabled         bool          // Enable/disable telemetry
	Insecure        bool          // Use insecure connection (dev only)
	CertFile        string        // Path to client certificate
	KeyFile         string        // Path to client key
	CAFile          string        // Path to CA certificate
}

const (
	// MetricsExporterNone keeps metrics local to the Prometheus scrape surface.
	MetricsExporterNone = "none"
	// MetricsExporterOTLP enables the optional OTLP metric push reader.
	MetricsExporterOTLP = "otlp"
)

// DefaultServiceName is the service.name every span carries unless
// OTEL_SERVICE_NAME says otherwise.
const DefaultServiceName = "helm-sovereign-os"

// ServiceNameFromEnv resolves service.name from the standard OTEL_SERVICE_NAME
// variable, falling back to DefaultServiceName when it is unset or blank.
//
// Without this the deployed name is a compile-time constant, so a backend query
// for the deployment's own name (e.g. `helm-ai-kernel`) matches nothing even
// though spans are arriving — the failure looks identical to "no spans at all".
func ServiceNameFromEnv() string {
	if name := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); name != "" {
		return name
	}
	return DefaultServiceName
}

// DefaultConfig returns production-ready defaults.
func DefaultConfig() *Config {
	return &Config{
		ServiceName:     ServiceNameFromEnv(),
		ServiceVersion:  "2.0.0",
		Environment:     "development",
		OTLPEndpoint:    "localhost:4317",
		MetricsExporter: MetricsExporterNone,
		SampleRate:      1.0, // Sample everything in dev
		BatchTimeout:    5 * time.Second,
		Enabled:         true,
		Insecure:        false, // Secure by default
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

	// prometheusRegistry is provider-local. Keeping the exporter off the
	// process-wide default registry makes repeated Services construction safe:
	// each provider owns one collector set and no registration can collide with
	// a previous provider.
	prometheusRegistry *prometheus.Registry
	otlpMetricReader   sdkmetric.Reader

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
	metricsExporter, err := normalizeMetricsExporter(config.MetricsExporter)
	if err != nil {
		return nil, err
	}
	config.MetricsExporter = metricsExporter

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
			semconv.DeploymentEnvironmentName(config.Environment),
			attribute.String("helm.component", "core"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Initialize tracing only when an OTLP endpoint is configured. A local
	// Prometheus scrape must not require a collector or create a background
	// trace exporter pointed at an empty target.
	if strings.TrimSpace(config.OTLPEndpoint) != "" {
		if err := p.initTraceProvider(ctx, res); err != nil {
			return nil, fmt.Errorf("failed to init trace provider: %w", err)
		}
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
		"metrics_exporter", config.MetricsExporter,
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
	metricsExporter, err := normalizeMetricsExporter(p.config.MetricsExporter)
	if err != nil {
		return err
	}
	p.config.MetricsExporter = metricsExporter

	registry := prometheus.NewRegistry()
	for _, collector := range []prometheus.Collector{
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	} {
		if err := registry.Register(collector); err != nil {
			return fmt.Errorf("failed to register process metrics collector: %w", err)
		}
	}

	prometheusExporter, err := otelprom.New(
		otelprom.WithRegisterer(registry),
		otelprom.WithoutTargetInfo(),
	)
	if err != nil {
		return fmt.Errorf("failed to create Prometheus metric exporter: %w", err)
	}
	readers := []sdkmetric.Reader{prometheusExporter}
	p.otlpMetricReader = nil
	if metricsExporter == MetricsExporterOTLP {
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
		p.otlpMetricReader = sdkmetric.NewPeriodicReader(exporter,
			sdkmetric.WithInterval(15*time.Second),
		)
		readers = append(readers, p.otlpMetricReader)
	}

	p.prometheusRegistry = registry
	p.meterProvider = sdkmetric.NewMeterProvider(meterProviderOptions(res, readers...)...)

	// Set as global provider. otelhttp resolves its meter from the global
	// provider (tracing.WrapEdgeHandler passes no WithMeterProvider), so this
	// assignment is what puts the views below on the kernel's HTTP metrics.
	otel.SetMeterProvider(p.meterProvider)

	return nil
}

// meterProviderOptions is the kernel's complete MeterProvider configuration,
// parameterised only by its reader.
//
// It is a function rather than an inline literal so a test can build the SAME
// provider with a ManualReader in place of the OTLP PeriodicReader. A
// cardinality view exercised only on a provider the test assembled itself would
// prove nothing about the provider the daemon runs.
func meterProviderOptions(res *resource.Resource, readers ...sdkmetric.Reader) []sdkmetric.Option {
	opts := []sdkmetric.Option{
		sdkmetric.WithResource(res),
	}
	for _, reader := range readers {
		if reader != nil {
			opts = append(opts, sdkmetric.WithReader(reader))
		}
	}
	for _, view := range HTTPServerMetricViews() {
		opts = append(opts, sdkmetric.WithView(view))
	}
	return opts
}

func normalizeMetricsExporter(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return MetricsExporterNone, nil
	}
	switch value {
	case MetricsExporterNone, MetricsExporterOTLP:
		return value, nil
	default:
		return "", fmt.Errorf("metrics exporter must be %q or %q, got %q", MetricsExporterNone, MetricsExporterOTLP, value)
	}
}

// PrometheusHandler returns this provider's local Prometheus scrape surface.
// It includes the OTel RED metrics, otelhttp server metrics, and the standard
// Go/process collectors. Governance counters are appended by the daemon's
// metrics handler because they have their own bounded in-memory collector.
func (p *Provider) PrometheusHandler() http.Handler {
	if p == nil || p.prometheusRegistry == nil {
		return nil
	}
	return promhttp.HandlerFor(p.prometheusRegistry, promhttp.HandlerOpts{})
}

// PrometheusGatherer returns this provider's local collector registry so a
// caller can compose it with other collectors before encoding one response.
func (p *Provider) PrometheusGatherer() prometheus.Gatherer {
	if p == nil || p.prometheusRegistry == nil {
		return nil
	}
	return p.prometheusRegistry
}

// httpServerMetricAttributeAllowlist is the complete set of attribute keys the
// kernel keeps on otelhttp's http.server.* instruments.
//
// otelhttp builds those attributes from semconv.MetricAttributes (otelhttp
// v0.65.0 handler.go:198 -> internal/semconv/server.go:345), a set that always
// includes server.address and server.port derived VERBATIM from the request's
// Host header. Host is client-supplied on every HTTP/1.1 request and net/http
// does not check it against the listener, so each distinct value mints a new,
// permanent series in the SDK's aggregation map. Anyone able to open a socket to
// the API port can therefore grow the process heap without bound, and without
// authenticating: the metric is recorded after the handler returns, whatever
// status it returned, 401 included.
//
// The bound cannot be applied at the call site.
// otelhttp.WithMetricAttributesFn only feeds MetricAttributes.
// AdditionalAttributes, so it can ADD keys and never remove the library's own.
// The MeterProvider's view pipeline is the only seam that can.
//
// What stays:
//
//   - http.route — the aggregation key the rest of HELM-495 exists to produce,
//     contributed by tracing.WrapEdgeHandler. Bounded by the mux's registered
//     patterns, with path parameters already folded into "{id}" by
//     http.ServeMux.
//   - http.request.method — the R and E of RED, and bounded: otelhttp folds
//     anything outside the nine known methods onto "_OTHER"
//     (internal/semconv/util.go standardizeHTTPMethod).
//   - http.response.status_code — the E of RED, bounded by the statuses the
//     kernel's own handlers write.
//
// What goes:
//
//   - server.address and server.port — the unbounded client-controlled pair
//     above. This is the finding.
//   - url.scheme — derived from req.TLS != nil, so it is constant for a given
//     listener. It discriminates nothing while multiplying every series.
//   - network.protocol.name and network.protocol.version — derived from
//     req.Proto, which Go's HTTP/1 server constrains to "HTTP/1.x", so they are
//     bounded (~10 values) rather than dangerous. They are dropped on cost, not
//     on safety: each surviving key multiplies route x method x status, and the
//     protocol is fixed per deployment, so the breakdown buys nothing an
//     operator would query. Re-adding either is a one-line, bounded change if a
//     mixed h1/h2 edge ever makes it interesting.
//
// This is an ALLOWLIST, not a denylist of the two offending keys, on purpose.
// The metric set is a subset of the SPAN set otelhttp builds a few lines earlier
// (RequestTraceAttrs), and that one already carries client-derived keys with far
// worse cardinality: user_agent.original, client.address, network.peer.port,
// url.path. Any of those migrating into the metric set — the two sets have moved
// together before — would walk straight through a denylist on the next
// dependency bump. Anything new arrives dropped instead, and is admitted here
// only after its cardinality has been reasoned about: the same default-DENY
// posture the kernel applies to unknown tools.
var httpServerMetricAttributeAllowlist = []attribute.Key{
	semconv.HTTPRequestMethodKey,
	semconv.HTTPResponseStatusCodeKey,
	semconv.HTTPRouteKey,
}

// HTTPServerMetricViews bounds the attribute set of every otelhttp server
// instrument to httpServerMetricAttributeAllowlist.
//
// It is exported because the bound is a property of the kernel, not of one
// constructor: any MeterProvider that ends up serving otelhttp — including one
// a test or a future exporter path builds — must apply these views, or the
// unbounded-Host series come straight back.
//
// The criteria matches by NAME with a wildcard rather than listing the three
// instruments otelhttp creates today (http.server.request.duration,
// http.server.request.body.size, http.server.response.body.size). One
// MetricAttributes set feeds all three, and the semantic conventions already
// define more of the family (http.server.active_requests) that a later otelhttp
// release can start emitting; a name list would leave the new one unfiltered.
// Instrumentation scope is deliberately not part of the criteria either —
// pinning otelhttp's scope name would make the guard fail OPEN the moment the
// library renames it.
//
// Leaving Stream.Aggregation nil is load-bearing: the SDK then keeps the
// aggregation the reader resolved, including the explicit bucket boundaries
// otelhttp advises for the duration histogram
// (sdk/metric pipeline.go HistogramAggregators). Setting an aggregation here
// would silently reset those buckets to the SDK default.
func HTTPServerMetricViews() []sdkmetric.View {
	return []sdkmetric.View{
		sdkmetric.NewView(
			sdkmetric.Instrument{Name: "http.server.*"},
			sdkmetric.Stream{
				AttributeFilter: attribute.NewAllowKeysFilter(httpServerMetricAttributeAllowlist...),
			},
		),
	}
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

// Shutdown gracefully shuts down the providers and returns the first error.
//
// It returns the error rather than swallowing it: this used to `return nil`
// unconditionally, which made every caller's `if err != nil { log... }` branch
// unreachable. An operator grepping the pod logs for that line then concluded
// the final flush had worked when it had exported nothing.
//
// The two providers get separate slices of the caller's budget instead of
// sharing one deadline. The trace batcher drains on its own
// context.Background() with a 30s export timeout, so against an unreachable
// collector it sits on whatever deadline it is given; sharing would leave the
// metric flush nothing and drop up to a full PeriodicReader interval (15s) of
// RED metrics on every such shutdown.
//
// The metric half runs on the CALLER's context, not a slice of it: it is last,
// so whatever the trace flush did not spend is already its own. That is what
// makes metricFlushReserve a floor rather than a quota — a trace flush that
// returns in 40ms hands the metric flush the remaining 4.96s.
func (p *Provider) Shutdown(ctx context.Context) error {
	var firstErr error
	if p.tracerProvider != nil {
		traceCtx, cancel := traceFlushBudget(ctx, metricFlushReserve)
		err := p.tracerProvider.Shutdown(traceCtx)
		cancel()
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to shutdown trace provider", "error", err)
			firstErr = err
		}
	}
	if p.meterProvider != nil {
		if err := p.meterProvider.Shutdown(ctx); err != nil {
			p.logger.ErrorContext(ctx, "failed to shutdown metric provider", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// metricFlushReserve is the slice of the shutdown budget the trace flush may
// not take.
//
// One second, because the metric half is a single PeriodicReader.Collect plus
// one OTLP export of a few hundred series: against a reachable collector that
// completes in milliseconds, and against an unreachable one no share of a 5s
// budget would have saved it. The trace half is the one that legitimately needs
// seconds — it drains a batch queue that has been accumulating since the last
// 5s BatchTimeout tick.
const metricFlushReserve = time.Second

// traceFlushBudget derives the trace flush's deadline from the time ACTUALLY
// remaining, holding reserve back for the metric flush that follows.
//
// This replaces an unconditional halving. The split's intent was right — the
// trace flush must not starve the metric flush — but halving is too blunt: with
// the daemon's 5s observabilityFlushTimeout it capped the trace flush at 2.5s,
// so a collector that needed 2.5-5s to accept the final batch lost it while the
// other 2.5s went unused. That is a real shape: the flush runs after the HTTP
// servers have drained, which is exactly when a collector is also being asked to
// absorb the last batch from every pod in the rollout.
//
// The reserve is capped at half the remaining time, which gives three
// properties worth stating:
//
//   - The trace flush never gets LESS than the old even split
//     (remaining-reserve >= remaining/2 for every reserve <= remaining/2), so
//     nothing regresses on a small budget.
//   - The metric flush is always left min(reserve, remaining/2), which is
//     strictly positive whenever any budget remains — it cannot be starved.
//   - On the daemon's 5s budget the split is 4s / >=1s instead of 2.5s / 2.5s.
//
// A context with no deadline is passed through with only a cancel attached; an
// already-expired one is passed through unchanged so the provider reports the
// real reason rather than a derived timeout.
func traceFlushBudget(ctx context.Context, reserve time.Duration) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.WithCancel(ctx)
	}
	if half := remaining / 2; reserve > half {
		reserve = half
	}
	return context.WithTimeout(ctx, remaining-reserve)
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
