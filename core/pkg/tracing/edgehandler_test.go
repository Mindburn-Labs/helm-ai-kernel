package tracing_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/correlation"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestWrapEdgeHandlerAdoptsAndStampsCorrelation(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})

	const inbound = "bf7171d9-4965-4c81-acf0-6dfe3042caa0"
	var inner correlation.ID
	h := tracing.WrapEdgeHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		inner, _ = correlation.From(r.Context())
		if got := r.Header.Get(correlation.Header); got != inbound {
			t.Errorf("downstream correlation header = %q, want %q", got, inbound)
		}
	}), "test.edge")
	req := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", nil)
	req.Header.Set(correlation.Header, inbound)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if string(inner) != inbound {
		t.Errorf("downstream correlation = %q, want %q", inner, inbound)
	}
	if got := rec.Header().Get(correlation.Header); got != inbound {
		t.Errorf("response correlation header = %q, want %q", got, inbound)
	}
	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d server spans, want 1", len(spans))
	}
	for _, attr := range spans[0].Attributes() {
		if string(attr.Key) == "helm.correlation_id" {
			if got := attr.Value.AsString(); got != inbound {
				t.Errorf("span correlation = %q, want %q", got, inbound)
			}
			return
		}
	}
	t.Error("server span has no helm.correlation_id attribute")
}

func TestWrapEdgeHandlerRootsInboundTraceAndLinksRemote(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})

	var innerSpan oteltrace.SpanContext
	var innerBaggage string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerSpan = oteltrace.SpanContextFromContext(r.Context())
		innerBaggage = baggage.FromContext(r.Context()).Member("tenant").Value()
	})
	h := tracing.WrapEdgeHandler(inner, "test.edge")

	const inboundTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	// The remote sampled flag is deliberately clear: it must not suppress the
	// kernel's new root span.
	req.Header.Set("traceparent", "00-"+inboundTraceID+"-00f067aa0ba902b7-00")
	req.Header.Set("baggage", "tenant=attacker")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !innerSpan.IsValid() {
		t.Fatal("inner handler saw no span in request context")
	}
	if got := innerSpan.TraceID().String(); got == inboundTraceID {
		t.Errorf("inner span adopted untrusted trace_id %s", got)
	}
	if !innerSpan.IsSampled() {
		t.Error("untrusted remote sampled flag suppressed the kernel span")
	}
	if innerBaggage != "" {
		t.Errorf("untrusted baggage reached the inner handler: tenant=%q", innerBaggage)
	}
	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d server spans, want 1", len(spans))
	}
	links := spans[0].Links()
	if len(links) != 1 || links[0].SpanContext.TraceID().String() != inboundTraceID {
		t.Errorf("server span links = %+v, want one link to inbound trace %s", links, inboundTraceID)
	}
}

func TestWrapEdgeHandlerDropsInboundTraceWithoutSDK(t *testing.T) {
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(noop.NewTracerProvider())
	t.Cleanup(func() { otel.SetTracerProvider(prev) })
	reader := recordEdgeMetrics(t)

	var logs bytes.Buffer
	logger := slog.New(tracing.NewSlogHandler(slog.NewTextHandler(&logs, nil)))
	var innerSpan oteltrace.SpanContext
	mux := http.NewServeMux()
	mux.HandleFunc("GET /probe/{id}", func(_ http.ResponseWriter, r *http.Request) {
		innerSpan = oteltrace.SpanContextFromContext(r.Context())
		logger.ErrorContext(r.Context(), "probe")
	})
	h := tracing.WrapEdgeHandler(mux, "test.edge")

	const inboundTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	req := httptest.NewRequest(http.MethodGet, "/probe/abc123", nil)
	req.Header.Set("traceparent", "00-"+inboundTraceID+"-00f067aa0ba902b7-01")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if innerSpan.IsValid() {
		t.Fatalf("inner handler retained remote span context without an SDK: %+v", innerSpan)
	}
	if strings.Contains(logs.String(), inboundTraceID) {
		t.Fatalf("log adopted untrusted trace_id without an SDK: %s", logs.String())
	}
	if got := durationRoutes(t, reader); !equalStrings(got, []string{"/probe/{id}"}) {
		t.Fatalf("routed no-SDK request metric routes = %v, want [/probe/{id}]", got)
	}
}
