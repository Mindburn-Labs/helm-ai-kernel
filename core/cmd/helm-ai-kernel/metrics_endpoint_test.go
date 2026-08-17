package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	helmmetrics "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/metrics"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
)

// allowPDP is the minimum inner PDP needed to drive one decision through
// TelemetryPDP, which is what registers and increments
// helm_kernel_decisions_total in the default registry.
type allowPDP struct{}

func (allowPDP) Evaluate(context.Context, *pdp.DecisionRequest) (*pdp.DecisionResponse, error) {
	return &pdp.DecisionResponse{Allow: true, ReasonCode: "OK"}, nil
}
func (allowPDP) Backend() pdp.Backend { return pdp.Backend("test") }
func (allowPDP) PolicyHash() string   { return "test" }

// TestMetricsEndpointServesBothSurfaces is the daemon-level HELM-477 acceptance
// check: one scrape of the endpoint the chart actually points at, carrying
// every family the issue says should be reachable.
//
// The package-level tests prove each surface in isolation. This one proves they
// arrive together through metricsGatherers, in a binary that links the real
// promauto counter rather than a stand-in — the counter Sergey's inventory
// found live in production code and unreachable by any path.
func TestMetricsEndpointServesBothSurfaces(t *testing.T) {
	// 1. The OTel surface, wired exactly as NewServices wires it.
	otelRegistry := prometheus.NewRegistry()
	cfg := observability.DefaultConfig()
	cfg.OTLPEndpoint = ""
	cfg.TracesEnabled = false
	cfg.MetricsExporter = observability.MetricsExporterNone
	cfg.PrometheusRegisterer = otelRegistry
	provider, err := observability.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("observability.New: %v", err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	// Handler built after the provider, as buildAPIHandler is built after
	// NewServices: otelhttp binds its meter at construction.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/probe/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	edge := tracing.WrapEdgeHandler(mux, "helm.api")
	edge.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/probe/abc123", nil))

	// 2. The client_golang surface: one real PDP decision.
	telemetry := pdp.NewTelemetryPDP(allowPDP{}, false)
	if _, err := telemetry.Evaluate(context.Background(), &pdp.DecisionRequest{
		Principal: "agent-1", Action: "read", Resource: "doc-1",
	}); err != nil {
		t.Fatalf("pdp evaluate: %v", err)
	}

	// 3. The governance surface.
	governance := helmmetrics.NewGovernanceMetrics()
	governance.RecordDecision(true, "search", "OK", "agent-1", 1500)

	services := &Services{OTelMetrics: otelRegistry}
	rec := httptest.NewRecorder()
	governance.PrometheusHandlerFor(metricsGatherers(services)...)(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	parser := expfmt.NewTextParser(model.UTF8Validation)
	parsed, err := parser.TextToMetricFamilies(strings.NewReader(body))
	if err != nil {
		t.Fatalf("/metrics is not valid Prometheus text format: %v\n---\n%s", err, body)
	}

	want := []string{
		// RED — the families the issue opens on, previously unreachable.
		"http_server_request_duration_seconds",
		// The live promauto counter nothing could read.
		"helm_kernel_decisions_total",
		// Runtime health for the component whose stability matters most.
		"go_goroutines",
		"process_resident_memory_bytes",
		// The governance families that were already served must survive.
		"helm_decisions_total",
		"helm_active_agents",
	}
	for _, name := range want {
		if _, ok := parsed[name]; !ok {
			got := make([]string, 0, len(parsed))
			for n := range parsed {
				got = append(got, n)
			}
			sort.Strings(got)
			t.Errorf("/metrics is missing %s\nfamilies served: %v", name, got)
		}
	}
}

// TestMetricsGatherersToleratesNilServices covers the daemon path where
// subsystem initialisation failed: the runtime families still say whether the
// process is alive, so /metrics must not panic or go empty.
func TestMetricsGatherersToleratesNilServices(t *testing.T) {
	if got := len(metricsGatherers(nil)); got != 1 {
		t.Errorf("metricsGatherers(nil) returned %d gatherers, want 1 (the default registry)", got)
	}
	if got := len(metricsGatherers(&Services{})); got != 1 {
		t.Errorf("metricsGatherers with no OTel registry returned %d gatherers, want 1", got)
	}
}
