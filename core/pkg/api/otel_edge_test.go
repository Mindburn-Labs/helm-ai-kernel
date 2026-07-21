package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// The REST edge participates in W3C trace context (HELM-333): an inbound
// traceparent is continued into a server span, and the span carries the
// helm.correlation_id attribute so traces join receipts 1:1.

// withSpanRecorder installs a recording TracerProvider as the global provider
// for the duration of the test and returns the recorder.
func withSpanRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })
	return sr
}

func TestOtelEdge_ContinuesInboundTraceAndStampsCorrelation(t *testing.T) {
	sr := withSpanRecorder(t)
	srv := newTestServer(t)

	const inboundTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const inboundCorr = "d2f1c3a4-5b6e-4f70-8a91-b2c3d4e5f601"
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("traceparent", "00-"+inboundTraceID+"-00f067aa0ba902b7-01")
	req.Header.Set("X-Helm-Correlation-ID", inboundCorr)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	spans := sr.Ended()
	if len(spans) == 0 {
		t.Fatal("no server span recorded at the REST edge")
	}
	span := spans[len(spans)-1]
	if got := span.SpanContext().TraceID().String(); got != inboundTraceID {
		t.Errorf("server span trace_id = %s, want continuation of inbound %s", got, inboundTraceID)
	}
	var corrAttr string
	for _, attr := range span.Attributes() {
		if string(attr.Key) == observability.HelmCorrelationID {
			corrAttr = attr.Value.AsString()
		}
	}
	if corrAttr != inboundCorr {
		t.Errorf("span %s = %q, want %q", observability.HelmCorrelationID, corrAttr, inboundCorr)
	}
}

func TestOtelEdge_MintedCorrelationStampedOnSpan(t *testing.T) {
	sr := withSpanRecorder(t)
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	echoed := w.Header().Get("X-Helm-Correlation-ID")
	if echoed == "" {
		t.Fatal("no correlation ID echoed on response")
	}
	spans := sr.Ended()
	if len(spans) == 0 {
		t.Fatal("no server span recorded at the REST edge")
	}
	var corrAttr string
	for _, attr := range spans[len(spans)-1].Attributes() {
		if string(attr.Key) == observability.HelmCorrelationID {
			corrAttr = attr.Value.AsString()
		}
	}
	if corrAttr != echoed {
		t.Errorf("span correlation attr = %q, want echoed minted id %q", corrAttr, echoed)
	}
}
