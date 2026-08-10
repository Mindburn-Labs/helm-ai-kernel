package observability

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// installKernelMeterProvider builds the meter provider the daemon builds — the
// same meterProviderOptions initMetricProvider passes, with only the OTLP
// PeriodicReader swapped for a ManualReader — and installs it globally.
//
// Installing it GLOBALLY is the load-bearing half. tracing.WrapEdgeHandler
// passes no otelhttp.WithMeterProvider, so otelhttp resolves
// otel.GetMeterProvider() when the handler is constructed. A view that lived on
// a provider nothing resolved would be a fix that does nothing, so the handler
// below is built after this returns, exactly as the daemon builds it after
// NewServices has run observability.New.
func installKernelMeterProvider(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(meterProviderOptions(resource.Default(), reader)...)
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(mp)
	t.Cleanup(func() {
		otel.SetMeterProvider(prev)
		_ = mp.Shutdown(context.Background())
	})
	return reader
}

// serverMetric is one collected http.server.* stream, flattened to the shape
// this file asserts on: its name and one attribute set per datapoint.
type serverMetric struct {
	name       string
	dataPoints []attribute.Set
	bounds     []float64
}

// collectServerMetrics returns every http.server.* instrument the reader holds.
//
// It walks the family rather than picking http.server.request.duration out of
// it: otelhttp records ONE attribute set into three instruments
// (internal/semconv/server.go RecordMetrics), so a view that matched only the
// duration histogram would leave the two body-size histograms carrying the
// unbounded Host. Selecting a single instrument here would hide exactly that.
func collectServerMetrics(t *testing.T, reader *sdkmetric.ManualReader) []serverMetric {
	t.Helper()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}

	var out []serverMetric
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if !strings.HasPrefix(m.Name, "http.server.") {
				continue
			}
			found := serverMetric{name: m.Name}
			switch data := m.Data.(type) {
			case metricdata.Histogram[float64]:
				if len(data.DataPoints) > 0 {
					found.bounds = append([]float64(nil), data.DataPoints[0].Bounds...)
				}
				for _, dp := range data.DataPoints {
					found.dataPoints = append(found.dataPoints, dp.Attributes)
				}
			case metricdata.Histogram[int64]:
				for _, dp := range data.DataPoints {
					found.dataPoints = append(found.dataPoints, dp.Attributes)
				}
			case metricdata.Sum[int64]:
				for _, dp := range data.DataPoints {
					found.dataPoints = append(found.dataPoints, dp.Attributes)
				}
			default:
				t.Fatalf("%s has unhandled data type %T: extend collectServerMetrics rather than "+
					"letting an instrument escape the cardinality assertions", m.Name, m.Data)
			}
			out = append(out, found)
		}
	}
	return out
}

func TestHTTPServerDurationKeepsRecommendedBuckets(t *testing.T) {
	reader := installKernelMeterProvider(t)
	probeHandler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/probe/abc123", nil))

	want := []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10}
	for _, metric := range collectServerMetrics(t, reader) {
		if metric.name != "http.server.request.duration" {
			continue
		}
		if !slices.Equal(metric.bounds, want) {
			t.Errorf("duration histogram bounds = %v, want OTel HTTP bounds %v", metric.bounds, want)
		}
		return
	}
	t.Fatal("http.server.request.duration was not recorded")
}

func attributeKeys(set attribute.Set) []string {
	keys := make([]string, 0, set.Len())
	for _, kv := range set.ToSlice() {
		keys = append(keys, string(kv.Key))
	}
	sort.Strings(keys)
	return keys
}

// sample renders at most two datapoints for a failure message. The failing case
// here is "hundreds of series where there should be one", so dumping them all
// buries the assertion under tens of kilobytes of attribute sets; two is enough
// to show which key is varying.
func sample(sets []attribute.Set) string {
	var b strings.Builder
	for i, set := range sets {
		if i == 2 {
			fmt.Fprintf(&b, "\n  ... and %d more", len(sets)-i)
			break
		}
		fmt.Fprintf(&b, "\n  %v", set.ToSlice())
	}
	return b.String()
}

// probeHandler is the edge under test: the real wrapper the daemon puts on its
// API, over a mux with one parameterised route.
func probeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/probe/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return tracing.WrapEdgeHandler(mux, "helm.api")
}

// TestHTTPServerMetricsDoNotGrowWithClientSuppliedHost is the BLOCKER guard.
//
// otelhttp's default metric attributes include server.address and server.port,
// both derived from the request's Host header (otelhttp v0.65.0
// internal/semconv/server.go MetricAttributes -> SplitHostPort(req.Host)).
// net/http does not validate Host against the listener, so without a view every
// distinct Host mints a permanent series in the SDK aggregation map: an
// unauthenticated caller who can open a socket to the API port grows the heap
// without bound.
//
// Distinct hosts in, ONE datapoint out. The assertion is on the count, not on
// the absence of a key, because the count is what the heap tracks.
func TestHTTPServerMetricsDoNotGrowWithClientSuppliedHost(t *testing.T) {
	reader := installKernelMeterProvider(t)
	h := probeHandler()

	const distinctHosts = 64
	for i := range distinctHosts {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/probe/abc123", nil)
		// Host and port both vary: server.port is derived from the same header
		// and is the second unbounded key.
		req.Host = fmt.Sprintf("attacker-%d.example:%d", i, 20000+i)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("request %d: status = %d, want %d — the probe never reached the route, so "+
				"this test is not measuring the served path", i, rec.Code, http.StatusNoContent)
		}
	}

	metrics := collectServerMetrics(t, reader)
	if len(metrics) == 0 {
		t.Fatal("no http.server.* instrument was recorded: the edge is not producing server " +
			"metrics at all, so this guard is asserting on nothing")
	}
	for _, m := range metrics {
		if got := len(m.dataPoints); got != 1 {
			t.Errorf("%s produced %d datapoints for %d requests that differ only in their "+
				"client-supplied Host header, want 1. Every distinct Host is a permanent series: "+
				"an unauthenticated caller can grow the kernel's heap without bound.\nattributes:%s",
				m.name, got, distinctHosts, sample(m.dataPoints))
		}
	}
}

// TestHTTPServerMetricAttributesAreTheAllowlist pins WHICH keys survive, on
// every instrument of the family.
//
// The count assertion above would still pass if the view dropped everything,
// including http.route — the aggregation key the rest of HELM-495 exists to
// produce. This is the other half: exactly the allowlist, no more and no less.
func TestHTTPServerMetricAttributesAreTheAllowlist(t *testing.T) {
	reader := installKernelMeterProvider(t)
	h := probeHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/probe/abc123", nil)
	req.Host = "kernel.internal:8443"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	want := []string{
		string(semconv.HTTPRequestMethodKey),
		string(semconv.HTTPResponseStatusCodeKey),
		string(semconv.HTTPRouteKey),
	}
	sort.Strings(want)

	metrics := collectServerMetrics(t, reader)
	if len(metrics) == 0 {
		t.Fatal("no http.server.* instrument was recorded")
	}
	for _, m := range metrics {
		if len(m.dataPoints) != 1 {
			t.Fatalf("%s produced %d datapoints for one request, want 1", m.name, len(m.dataPoints))
		}
		set := m.dataPoints[0]
		if got := attributeKeys(set); !equalStrings(got, want) {
			t.Errorf("%s attribute keys = %v, want %v.\n"+
				"Extra keys are cardinality the allowlist was meant to remove; a missing "+
				"http.route means the latency histogram can no longer be split per route or "+
				"joined to its span.", m.name, got, want)
		}
		if v, ok := set.Value(semconv.HTTPRouteKey); !ok || v.AsString() != "/api/v1/probe/{id}" {
			t.Errorf("%s http.route = %v (present=%t), want %q", m.name, v, ok, "/api/v1/probe/{id}")
		}
		if v, ok := set.Value(semconv.HTTPRequestMethodKey); !ok || v.AsString() != http.MethodGet {
			t.Errorf("%s http.request.method = %v (present=%t), want %q", m.name, v, ok, http.MethodGet)
		}
		if v, ok := set.Value(semconv.HTTPResponseStatusCodeKey); !ok || v.AsInt64() != http.StatusNoContent {
			t.Errorf("%s http.response.status_code = %v (present=%t), want %d",
				m.name, v, ok, http.StatusNoContent)
		}
	}
}

// TestHTTPServerMetricsSplitOnRouteMethodAndStatus proves the surviving keys
// still do their job: the view bounds cardinality, it does not collapse the
// signal. Three requests that differ on the three allowlisted axes must produce
// three datapoints.
//
// Without this, deleting keys from httpServerMetricAttributeAllowlist would only
// have to keep the count-is-one assertions green, which an empty allowlist does.
func TestHTTPServerMetricsSplitOnRouteMethodAndStatus(t *testing.T) {
	reader := installKernelMeterProvider(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/probe/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/probe/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("GET /api/v1/other", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := tracing.WrapEdgeHandler(mux, "helm.api")

	for _, probe := range []struct {
		method string
		target string
	}{
		{http.MethodGet, "/api/v1/probe/abc123"},  // route A, GET, 204
		{http.MethodPost, "/api/v1/probe/abc123"}, // same route, different method AND status
		{http.MethodGet, "/api/v1/other"},         // different route
	} {
		req := httptest.NewRequest(probe.method, probe.target, nil)
		req.Host = "kernel.internal:8443" // identical for all three
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	for _, m := range collectServerMetrics(t, reader) {
		if got := len(m.dataPoints); got != 3 {
			t.Errorf("%s produced %d datapoints for 3 requests differing by route, method and "+
				"status, want 3: the allowlist has dropped a key RED depends on.\nattributes:%s",
				m.name, got, sample(m.dataPoints))
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
