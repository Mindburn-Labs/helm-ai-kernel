package tracing_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func TestWrapEdgeHandlerContinuesInboundTraceparent(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})

	var innerSpan oteltrace.SpanContext
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerSpan = oteltrace.SpanContextFromContext(r.Context())
	})
	h := tracing.WrapEdgeHandler(inner, "test.edge")

	const inboundTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("traceparent", "00-"+inboundTraceID+"-00f067aa0ba902b7-01")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !innerSpan.IsValid() {
		t.Fatal("inner handler saw no span in request context")
	}
	if got := innerSpan.TraceID().String(); got != inboundTraceID {
		t.Errorf("inner span trace_id = %s, want continuation of %s", got, inboundTraceID)
	}
	if spans := sr.Ended(); len(spans) == 0 {
		t.Error("no server span recorded")
	}
}
