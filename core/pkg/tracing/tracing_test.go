package tracing_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/tracing"
)

// ── NoopTracer ────────────────────────────────────────────────────────────────

func TestNoopTracer_StartSpan_ReturnsSpan(t *testing.T) {
	tr := tracing.NewNoopTracer()
	ctx := context.Background()

	ctx2, span := tr.StartSpan(ctx, "test.op")
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	if span.Name != "test.op" {
		t.Errorf("expected name %q, got %q", "test.op", span.Name)
	}
	if span.StartTimeMs == 0 {
		t.Error("StartTimeMs should be set")
	}
	if string(span.TraceID) == "" {
		t.Error("TraceID should be non-empty")
	}
	if string(span.SpanID) == "" {
		t.Error("SpanID should be non-empty")
	}
	if ctx2 == ctx {
		t.Error("StartSpan should return a derived context")
	}
}

func TestNoopTracer_EndSpan_SetsEndTime(t *testing.T) {
	tr := tracing.NewNoopTracer()
	ctx := context.Background()

	_, span := tr.StartSpan(ctx, "test.op")
	tr.EndSpan(span, nil)

	if span.EndTimeMs == 0 {
		t.Error("EndTimeMs should be set after EndSpan")
	}
	if span.Status != tracing.StatusOK {
		t.Errorf("expected status %q, got %q", tracing.StatusOK, span.Status)
	}
}

func TestNoopTracer_EndSpan_ErrorStatus(t *testing.T) {
	tr := tracing.NewNoopTracer()
	ctx := context.Background()

	_, span := tr.StartSpan(ctx, "test.op")
	tr.EndSpan(span, errors.New("boom"))

	if span.Status != tracing.StatusError {
		t.Errorf("expected status %q, got %q", tracing.StatusError, span.Status)
	}
}

func TestNoopTracer_EndSpan_NilSafe(t *testing.T) {
	tr := tracing.NewNoopTracer()
	// Must not panic.
	tr.EndSpan(nil, nil)
}

func TestNoopTracer_Export_Noop(t *testing.T) {
	tr := tracing.NewNoopTracer()
	err := tr.Export(context.Background(), []tracing.Span{})
	if err != nil {
		t.Errorf("Export should not fail: %v", err)
	}
}

// ── Span propagation ──────────────────────────────────────────────────────────

func TestSpanFromContext_EmptyContext(t *testing.T) {
	_, ok := tracing.SpanFromContext(context.Background())
	if ok {
		t.Error("expected no span in empty context")
	}
}

func TestNoopTracer_SpanPropagation(t *testing.T) {
	tr := tracing.NewNoopTracer()
	ctx := context.Background()

	ctx, parent := tr.StartSpan(ctx, "parent")
	ctx, child := tr.StartSpan(ctx, "child")

	if child.TraceID != parent.TraceID {
		t.Errorf("child trace ID %q should match parent %q", child.TraceID, parent.TraceID)
	}
	if child.ParentID != parent.SpanID {
		t.Errorf("child parent ID %q should match parent span ID %q", child.ParentID, parent.SpanID)
	}

	// Recover span from context.
	got, ok := tracing.SpanFromContext(ctx)
	if !ok {
		t.Fatal("expected span in context")
	}
	if got.SpanID != child.SpanID {
		t.Errorf("context span should be the child, got %q want %q", got.SpanID, child.SpanID)
	}
}

// ── Correlation ID ────────────────────────────────────────────────────────────

func TestCorrelationID_RoundTrip(t *testing.T) {
	id := tracing.NewCorrelationID()
	if string(id) == "" {
		t.Fatal("NewCorrelationID returned empty string")
	}

	ctx := tracing.WithCorrelationID(context.Background(), id)
	got, ok := tracing.GetCorrelationID(ctx)
	if !ok {
		t.Fatal("expected correlation ID in context")
	}
	if got != id {
		t.Errorf("got %q, want %q", got, id)
	}
}

func TestGetCorrelationID_EmptyContext(t *testing.T) {
	_, ok := tracing.GetCorrelationID(context.Background())
	if ok {
		t.Error("expected no correlation ID in empty context")
	}
}

func TestNewCorrelationID_Unique(t *testing.T) {
	ids := make(map[tracing.CorrelationID]struct{})
	for i := range 100 {
		id := tracing.NewCorrelationID()
		if _, dup := ids[id]; dup {
			t.Fatalf("duplicate correlation ID at iteration %d: %q", i, id)
		}
		ids[id] = struct{}{}
	}
}

// ── HTTP header injection / extraction ───────────────────────────────────────

func TestInjectHTTPHeaders_WritesHeader(t *testing.T) {
	id := tracing.NewCorrelationID()
	ctx := tracing.WithCorrelationID(context.Background(), id)

	headers := http.Header{}
	tracing.InjectHTTPHeaders(ctx, headers)

	if got := headers.Get("X-Helm-Correlation-ID"); got != string(id) {
		t.Errorf("expected header %q, got %q", id, got)
	}
}

func TestInjectHTTPHeaders_NoopWhenMissing(t *testing.T) {
	headers := http.Header{}
	tracing.InjectHTTPHeaders(context.Background(), headers)

	if v := headers.Get("X-Helm-Correlation-ID"); v != "" {
		t.Errorf("expected empty header, got %q", v)
	}
}

func TestExtractHTTPHeaders_ReadsHeader(t *testing.T) {
	want := tracing.CorrelationID("my-test-id")
	headers := http.Header{}
	headers.Set("X-Helm-Correlation-ID", string(want))

	got, ok := tracing.ExtractHTTPHeaders(headers)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractHTTPHeaders_MissingHeader(t *testing.T) {
	_, ok := tracing.ExtractHTTPHeaders(http.Header{})
	if ok {
		t.Error("expected ok=false when header is absent")
	}
}

func TestInjectExtract_RoundTrip(t *testing.T) {
	id := tracing.NewCorrelationID()
	ctx := tracing.WithCorrelationID(context.Background(), id)

	headers := http.Header{}
	tracing.InjectHTTPHeaders(ctx, headers)

	extracted, ok := tracing.ExtractHTTPHeaders(headers)
	if !ok {
		t.Fatal("expected ok=true after inject→extract")
	}
	if extracted != id {
		t.Errorf("round-trip mismatch: got %q want %q", extracted, id)
	}
}

// ── LangSmith exporter ────────────────────────────────────────────────────────

func TestLangSmithExporter_ExportsSpans(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/runs/batch") {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		if r.Header.Get("X-API-Key") == "" {
			t.Error("missing X-API-Key header")
		}
		body, _ := io.ReadAll(r.Body)
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exporter := tracing.NewLangSmithExporter("test-key", srv.URL)

	spans := []tracing.Span{
		{
			TraceID:     "trace-1",
			SpanID:      "span-1",
			Name:        "helm.decision",
			StartTimeMs: 1_700_000_000_000,
			EndTimeMs:   1_700_000_001_000,
			Status:      tracing.StatusOK,
			Attributes:  map[string]string{"verdict": "ALLOW"},
		},
	}

	if err := exporter.Export(context.Background(), spans); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	if len(received) == 0 {
		t.Fatal("server received no payload")
	}

	var runs []map[string]any
	if err := json.Unmarshal(received, &runs); err != nil {
		t.Fatalf("invalid JSON: %v (body: %s)", err, received)
	}
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	if runs[0]["id"] != "span-1" {
		t.Errorf("unexpected id: %v", runs[0]["id"])
	}
}

func TestLangSmithExporter_EmptySpans(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be called for empty span list")
	}))
	defer srv.Close()

	exporter := tracing.NewLangSmithExporter("key", srv.URL)
	if err := exporter.Export(context.Background(), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLangSmithExporter_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	exporter := tracing.NewLangSmithExporter("key", srv.URL)
	spans := []tracing.Span{{TraceID: "t", SpanID: "s", Name: "x", StartTimeMs: 1}}
	err := exporter.Export(context.Background(), spans)
	if err == nil {
		t.Error("expected error on 5xx response")
	}
}

// ── Langfuse exporter ─────────────────────────────────────────────────────────

func TestLangfuseExporter_ExportsSpans(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/public/ingestion") {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			t.Errorf("expected Basic auth, got %q", auth)
		}
		body, _ := io.ReadAll(r.Body)
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exporter := tracing.NewLangfuseExporter("pk", "sk", srv.URL)

	spans := []tracing.Span{
		{
			TraceID:     "trace-1",
			SpanID:      "span-2",
			Name:        "helm.policy",
			StartTimeMs: 1_700_000_000_000,
			EndTimeMs:   1_700_000_002_000,
			Status:      tracing.StatusError,
		},
	}

	if err := exporter.Export(context.Background(), spans); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	if len(received) == 0 {
		t.Fatal("server received no payload")
	}

	var batch map[string]any
	if err := json.Unmarshal(received, &batch); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	events, ok := batch["batch"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("expected batch with 1 event, got: %v", batch)
	}
}

func TestLangfuseExporter_EmptySpans(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be called for empty span list")
	}))
	defer srv.Close()

	exporter := tracing.NewLangfuseExporter("pk", "sk", srv.URL)
	if err := exporter.Export(context.Background(), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLangfuseExporter_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	exporter := tracing.NewLangfuseExporter("pk", "sk", srv.URL)
	spans := []tracing.Span{{TraceID: "t", SpanID: "s", Name: "x", StartTimeMs: 1}}
	err := exporter.Export(context.Background(), spans)
	if err == nil {
		t.Error("expected error on 4xx response")
	}
}

// ── Span JSON serialisation ────────────────────────────────────────────────────

func TestSpan_JSONRoundTrip(t *testing.T) {
	original := tracing.Span{
		TraceID:     "trace-abc",
		SpanID:      "span-xyz",
		ParentID:    "parent-123",
		Name:        "helm.evaluation",
		StartTimeMs: 1_700_000_000_000,
		EndTimeMs:   1_700_000_001_000,
		Status:      tracing.StatusOK,
		Attributes:  map[string]string{"policy": "baseline"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded tracing.Span
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.TraceID != original.TraceID {
		t.Errorf("TraceID mismatch: %q vs %q", decoded.TraceID, original.TraceID)
	}
	if decoded.SpanID != original.SpanID {
		t.Errorf("SpanID mismatch: %q vs %q", decoded.SpanID, original.SpanID)
	}
	if decoded.Status != original.Status {
		t.Errorf("Status mismatch: %q vs %q", decoded.Status, original.Status)
	}
}

func TestSpan_OmitsParentIDWhenEmpty(t *testing.T) {
	s := tracing.Span{
		TraceID:     "t",
		SpanID:      "s",
		Name:        "op",
		StartTimeMs: 1,
		Status:      tracing.StatusOK,
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(data), "parent_id") {
		t.Errorf("parent_id should be omitted when empty, got: %s", data)
	}
}

// ── OTelTracer ────────────────────────────────────────────────────────────────

func TestOTelTracer_NoEndpoint_StartEndSpan(t *testing.T) {
	tr, err := tracing.NewOTelTracer("test-service")
	if err != nil {
		t.Fatalf("NewOTelTracer failed: %v", err)
	}
	defer tr.Shutdown(context.Background())

	ctx := context.Background()
	ctx, span := tr.StartSpan(ctx, "otel.test")
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	if span.Name != "otel.test" {
		t.Errorf("expected name %q, got %q", "otel.test", span.Name)
	}
	if span.StartTimeMs == 0 {
		t.Error("StartTimeMs should be set")
	}

	tr.EndSpan(span, nil)
	if span.EndTimeMs == 0 {
		t.Error("EndTimeMs should be set after EndSpan")
	}
	if span.Status != tracing.StatusOK {
		t.Errorf("expected %q, got %q", tracing.StatusOK, span.Status)
	}
}

func TestOTelTracer_ErrorStatus(t *testing.T) {
	tr, err := tracing.NewOTelTracer("test-service")
	if err != nil {
		t.Fatalf("NewOTelTracer failed: %v", err)
	}
	defer tr.Shutdown(context.Background())

	_, span := tr.StartSpan(context.Background(), "otel.err")
	tr.EndSpan(span, fmt.Errorf("policy denied"))

	if span.Status != tracing.StatusError {
		t.Errorf("expected %q, got %q", tracing.StatusError, span.Status)
	}
}

func TestOTelTracer_AddExporter_CalledOnEndSpan(t *testing.T) {
	tr, err := tracing.NewOTelTracer("test-service")
	if err != nil {
		t.Fatalf("NewOTelTracer failed: %v", err)
	}
	defer tr.Shutdown(context.Background())

	exported := make([]tracing.Span, 0)
	tr.AddExporter(&captureExporter{spans: &exported})

	_, span := tr.StartSpan(context.Background(), "captured.op")
	tr.EndSpan(span, nil)

	if len(exported) != 1 {
		t.Fatalf("expected 1 exported span, got %d", len(exported))
	}
	if exported[0].Name != "captured.op" {
		t.Errorf("unexpected span name: %q", exported[0].Name)
	}
}

// captureExporter collects spans for test assertions.
type captureExporter struct {
	spans *[]tracing.Span
}

func (c *captureExporter) Export(_ context.Context, spans []tracing.Span) error {
	*c.spans = append(*c.spans, spans...)
	return nil
}
