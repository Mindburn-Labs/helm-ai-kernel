package tracing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// logLine runs fn against a logger built on NewSlogHandler over a JSON handler
// and returns the decoded single log record.
func logLine(t *testing.T, ctx context.Context, msg string) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(tracing.NewSlogHandler(slog.NewJSONHandler(&buf, nil)))
	logger.InfoContext(ctx, msg)
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("decode log record: %v (raw: %q)", err, buf.String())
	}
	return rec
}

func TestSlogHandlerStampsCorrelationID(t *testing.T) {
	corr := tracing.NewCorrelationID()
	ctx := tracing.WithCorrelationID(context.Background(), corr)

	rec := logLine(t, ctx, "hello")

	if got, ok := rec["correlation_id"]; !ok || got != string(corr) {
		t.Fatalf("correlation_id = %v (present=%v), want %q", got, ok, corr)
	}
}

func TestSlogHandlerStampsTraceAndSpanID(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	defer span.End()
	sc := span.SpanContext()

	rec := logLine(t, ctx, "hello")

	if got := rec["trace_id"]; got != sc.TraceID().String() {
		t.Fatalf("trace_id = %v, want %s", got, sc.TraceID())
	}
	if got := rec["span_id"]; got != sc.SpanID().String() {
		t.Fatalf("span_id = %v, want %s", got, sc.SpanID())
	}
}

func TestSlogHandlerWithoutIdentityAddsNothing(t *testing.T) {
	rec := logLine(t, context.Background(), "hello")

	for _, k := range []string{"correlation_id", "trace_id", "span_id"} {
		if v, ok := rec[k]; ok {
			t.Fatalf("unexpected %s = %v on record without identity in ctx", k, v)
		}
	}
}
