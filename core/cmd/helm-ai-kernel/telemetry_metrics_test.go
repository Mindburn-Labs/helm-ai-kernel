package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
	"go.opentelemetry.io/otel"
)

func TestMetricsExporterFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		want string
		err  bool
	}{
		{name: "unset", env: "", want: "none"},
		{name: "none", env: "none", want: "none"},
		{name: "otlp", env: "otlp", want: "otlp"},
		{name: "invalid", env: "prometheus", err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_METRICS_EXPORTER", tc.env)
			got, err := metricsExporterFromEnv()
			if tc.err {
				if err == nil {
					t.Fatalf("metricsExporterFromEnv() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("metricsExporterFromEnv() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("metricsExporterFromEnv() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMetricsHandlerComposesGovernanceAndRuntimeFamilies(t *testing.T) {
	previousMeter := otel.GetMeterProvider()
	provider, err := observability.New(context.Background(), &observability.Config{
		ServiceName:     "kernel.metrics.test",
		ServiceVersion:  "test",
		Environment:     "test",
		OTLPEndpoint:    "",
		MetricsExporter: observability.MetricsExporterNone,
		SampleRate:      1,
		BatchTimeout:    time.Second,
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("observability.New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
		otel.SetMeterProvider(previousMeter)
	})

	provider.RecordRequest(context.Background())
	verificationMetrics.RecordDecision(false, "metrics.test", "bounded_test_reason", "test-agent", 1000)
	traced := tracing.WrapEdgeHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "metrics.test")
	request := httptest.NewRequest(http.MethodGet, "http://kernel.test/metrics-probe", nil)
	traced.ServeHTTP(httptest.NewRecorder(), request)

	handler := metricsHandler(&Services{Observability: provider})
	for _, tc := range []struct {
		name        string
		openMetrics bool
	}{
		{name: "prometheus", openMetrics: false},
		{name: "openmetrics", openMetrics: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.openMetrics {
				request.Header.Set("Accept", "application/openmetrics-text; version=1.0.0")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			body := response.Body.String()
			if response.Code != http.StatusOK {
				t.Fatalf("metrics status = %d, want %d", response.Code, http.StatusOK)
			}
			for _, family := range []string{
				"helm_decisions_total",
				"helm_requests_total",
				"http_server_request_duration_seconds",
				"go_goroutines",
				"process_cpu_seconds_total",
			} {
				if !strings.Contains(body, family) {
					t.Errorf("metrics response missing family %q", family)
				}
			}
			if tc.openMetrics {
				trimmed := strings.TrimSpace(body)
				if !strings.HasSuffix(trimmed, "# EOF") {
					t.Fatalf("OpenMetrics response does not end with # EOF")
				}
				if strings.Count(trimmed, "# EOF") != 1 {
					t.Fatalf("OpenMetrics response has unexpected # EOF count")
				}
			}
		})
	}
}
