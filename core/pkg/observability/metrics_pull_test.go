package observability

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
)

// installPullProvider builds the provider the daemon builds for the DEFAULT
// posture after HELM-477: no OTLP endpoint anywhere, telemetry "off" as far as
// the chart is concerned, and a prometheus reader feeding /metrics.
//
// It goes through observability.New rather than assembling a MeterProvider
// itself, because the thing under test is precisely that New installs a
// readable metric pipeline when nothing configured an exporter. A test that
// built its own provider would pass even with the bug fully restored.
func installPullProvider(t *testing.T, exporter, endpoint string) (*prometheus.Registry, *Provider) {
	t.Helper()

	reg := prometheus.NewRegistry()
	cfg := DefaultConfig()
	cfg.OTLPEndpoint = endpoint
	cfg.TracesEnabled = endpoint != ""
	cfg.Insecure = true
	cfg.MetricsExporter = exporter
	cfg.PrometheusRegisterer = reg

	p, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("observability.New: %v", err)
	}
	t.Cleanup(func() {
		_ = p.Shutdown(context.Background())
	})
	return reg, p
}

// probeEdge is the edge under test: the real wrapper the daemon puts on its
// API, over a mux with one parameterised route.
//
// It is constructed AFTER the provider is installed, exactly as the daemon
// builds buildAPIHandler after NewServices. otelhttp binds its meter once at
// construction, so the reverse order silently yields a no-op meter — the
// failure this ordering exists to avoid.
func probeEdge() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/probe/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/boom", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	return tracing.WrapEdgeHandler(mux, "helm.api")
}

func gatherNames(t *testing.T, reg *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := make(map[string]*dto.MetricFamily, len(families))
	for _, mf := range families {
		out[mf.GetName()] = mf
	}
	return out
}

func findFamily(families map[string]*dto.MetricFamily, substr string) (string, *dto.MetricFamily) {
	names := make([]string, 0, len(families))
	for name := range families {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.Contains(name, substr) {
			return name, families[name]
		}
	}
	return "", nil
}

// TestPullSurfaceExposesHTTPServerRED is the HELM-477 acceptance test.
//
// Before the fix the kernel's request-level RED signal existed and was
// unreachable: otelhttp recorded http.server.* into a MeterProvider that was
// only ever built when OTEL_EXPORTER_OTLP_ENDPOINT was set, and even then only
// exported over OTLP — a transport HELM-469 had already ruled out. The QA
// dashboard could show governance counters and no request rate, error rate or
// duration for the service itself.
//
// Here nothing is configured at all — no endpoint, no exporter — and the
// families must still be readable from the pull surface.
func TestPullSurfaceExposesHTTPServerRED(t *testing.T) {
	reg, _ := installPullProvider(t, MetricsExporterNone, "")

	edge := probeEdge()
	edge.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/probe/abc123", nil))
	edge.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/boom", nil))

	families := gatherNames(t, reg)
	name, mf := findFamily(families, "http_server_request_duration")
	if mf == nil {
		got := make([]string, 0, len(families))
		for n := range families {
			got = append(got, n)
		}
		sort.Strings(got)
		t.Fatalf("no http_server_request_duration family on the pull surface; got %v", got)
	}

	// Rate and Duration: the histogram carries a count and a sum per series.
	var total uint64
	for _, m := range mf.GetMetric() {
		total += m.GetHistogram().GetSampleCount()
	}
	if total != 2 {
		t.Errorf("%s sample count = %d, want 2 (one per request)", name, total)
	}

	// Errors: the 500 must be distinguishable from the 204, which is what makes
	// this a RED signal rather than a request counter.
	statuses := map[string]bool{}
	routes := map[string]bool{}
	for _, m := range mf.GetMetric() {
		for _, lp := range m.GetLabel() {
			switch lp.GetName() {
			case "http_response_status_code":
				statuses[lp.GetValue()] = true
			case "http_route":
				routes[lp.GetValue()] = true
			case "server_address", "server_port":
				// The HELM-495 cardinality bound must survive the new reader:
				// these are derived verbatim from the client-supplied Host.
				t.Errorf("%s carries unbounded label %s — HTTPServerMetricViews is not applied to the prometheus reader", name, lp.GetName())
			}
		}
	}
	for _, want := range []string{"204", "500"} {
		if !statuses[want] {
			t.Errorf("%s has no series for status %s; statuses seen: %v", name, want, keys(statuses))
		}
	}
	// http.route proves the route identity HELM-495 exists to produce survived
	// the translation to Prometheus, so a panel can group by endpoint.
	if !routes["/api/v1/probe/{id}"] {
		t.Errorf("%s has no series for route /api/v1/probe/{id}; routes seen: %v", name, keys(routes))
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// fakeMetricsCollector counts OTLP metric export requests. It implements only
// the metrics service: a trace export must not reach it, and if the export
// lanes are ever crossed the RPC fails loudly rather than being miscounted.
type fakeMetricsCollector struct {
	collectormetricspb.UnimplementedMetricsServiceServer
	mu sync.Mutex
	n  int
}

func (f *fakeMetricsCollector) Export(context.Context, *collectormetricspb.ExportMetricsServiceRequest) (*collectormetricspb.ExportMetricsServiceResponse, error) {
	f.mu.Lock()
	f.n++
	f.mu.Unlock()
	return &collectormetricspb.ExportMetricsServiceResponse{}, nil
}

func (f *fakeMetricsCollector) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

func startFakeCollector(t *testing.T) (*fakeMetricsCollector, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	fake := &fakeMetricsCollector{}
	collectormetricspb.RegisterMetricsServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return fake, lis.Addr().String()
}

// TestOTLPEndpointAloneDoesNotPushMetrics is the second half of HELM-477.
//
// The reported defect: services.go gated observability on
// OTEL_EXPORTER_OTLP_ENDPOINT, and observability.New then raised the trace
// provider AND the MeterProvider in one call. So the moment a chart handed the
// kernel an endpoint so it could export TRACES, it also started pushing
// METRICS at a collector with no metrics pipeline, and the exporter retried in
// a loop against a component with no owner for that signal.
//
// An endpoint is configured here — traces are on — and the metric push must
// stay silent because nothing selected it.
func TestOTLPEndpointAloneDoesNotPushMetrics(t *testing.T) {
	fake, addr := startFakeCollector(t)
	_, p := installPullProvider(t, MetricsExporterNone, addr)

	// Record something, then force whatever readers exist to flush. With the
	// defect restored this is where the PeriodicReader ships its batch.
	p.RecordRequest(context.Background())
	if p.meterProvider != nil {
		if err := p.meterProvider.ForceFlush(context.Background()); err != nil {
			t.Fatalf("force flush: %v", err)
		}
	}
	time.Sleep(200 * time.Millisecond)

	if got := fake.count(); got != 0 {
		t.Errorf("OTLP metric exports = %d, want 0: an endpoint for traces must not enable the metric push", got)
	}
}

// TestMetricsExporterOTLPPushes is the companion that keeps the test above
// honest. Without it, a change that broke the OTLP metric path outright would
// leave TestOTLPEndpointAloneDoesNotPushMetrics permanently, silently green.
func TestMetricsExporterOTLPPushes(t *testing.T) {
	fake, addr := startFakeCollector(t)
	_, p := installPullProvider(t, MetricsExporterOTLP, addr)

	p.RecordRequest(context.Background())
	if p.meterProvider == nil {
		t.Fatal("no meter provider installed with the otlp exporter selected")
	}
	if err := p.meterProvider.ForceFlush(context.Background()); err != nil {
		t.Fatalf("force flush: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fake.count() > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("OTLP metric exports = 0, want at least 1 when OTEL_METRICS_EXPORTER=otlp")
}

// TestOTLPMetricsWithoutEndpointIsAnError guards the one combination that
// cannot be honoured: a push with nowhere to push to. Failing here beats
// silently downgrading to no export, which is the class of bug this issue is.
func TestOTLPMetricsWithoutEndpointIsAnError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OTLPEndpoint = ""
	cfg.TracesEnabled = false
	cfg.MetricsExporter = MetricsExporterOTLP
	cfg.PrometheusRegisterer = prometheus.NewRegistry()

	if _, err := New(context.Background(), cfg); err == nil {
		t.Error("New succeeded with MetricsExporter=otlp and no endpoint, want an error")
	}
}

// TestNoReadersInstallsNoProvider preserves the pre-HELM-477 posture for
// library callers that opt out of both surfaces: the global MeterProvider is
// left alone rather than replaced by one nothing reads.
func TestNoReadersInstallsNoProvider(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OTLPEndpoint = ""
	cfg.TracesEnabled = false
	cfg.MetricsExporter = MetricsExporterNone
	cfg.PrometheusRegisterer = nil

	p, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	if p.meterProvider != nil {
		t.Error("a MeterProvider was installed with neither a pull nor a push reader")
	}
}

func TestMetricsExporterFromEnv(t *testing.T) {
	cases := []struct {
		env  string
		want string
	}{
		{"", MetricsExporterNone},
		{"none", MetricsExporterNone},
		{"otlp", MetricsExporterOTLP},
		{"OTLP", MetricsExporterOTLP},
		{"  otlp  ", MetricsExporterOTLP},
		// The pull surface is unconditional, so "prometheus" is already
		// satisfied and selects no push.
		{"prometheus", MetricsExporterNone},
		// Unrecognised transports fail closed rather than guessing.
		{"console", MetricsExporterNone},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%q", tc.env), func(t *testing.T) {
			t.Setenv("OTEL_METRICS_EXPORTER", tc.env)
			if got := MetricsExporterFromEnv(); got != tc.want {
				t.Errorf("MetricsExporterFromEnv() = %q, want %q", got, tc.want)
			}
		})
	}
}
