package sumo

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func sampleSpan(t *testing.T) sdktrace.ReadOnlySpan {
	t.Helper()
	tid, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	sid, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	stub := tracetest.SpanStub{
		Name: "gen_ai.tool_call",
		SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: tid,
			SpanID:  sid,
		}),
		StartTime: time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 4, 28, 10, 0, 0, 1_500_000, time.UTC),
		Attributes: []attribute.KeyValue{
			attribute.String(observability.GenAISystem, "openai"),
			attribute.String(observability.GenAIRequestModel, "gpt-4o"),
			attribute.String(observability.GenAIToolName, "search_web"),
			attribute.String(observability.GenAIToolCallID, "corr-1"),
			attribute.Int64(observability.GenAIUsageInputTokens, 120),
			attribute.Int64(observability.GenAIUsageOutputTokens, 35),
			attribute.String(observability.HelmVerdict, "ALLOW"),
			attribute.String(observability.HelmPolicyID, "bundle/rule-1"),
			attribute.String(observability.HelmCorrelationID, "corr-1"),
		},
	}
	return stub.Snapshot()
}

func TestNew_RejectsMissingURL(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected missing URL to fail")
	}
}

func TestNew_AppliesDefaults(t *testing.T) {
	e, err := New(Config{URL: "http://example/sumo"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.cfg.Name != "helm-ai-kernel" {
		t.Errorf("Name default = %q", e.cfg.Name)
	}
	if e.cfg.Category != "helm/governance" {
		t.Errorf("Category default = %q", e.cfg.Category)
	}
}

func TestExportSpans_ProducesNDJSON(t *testing.T) {
	type captured struct {
		ContentType string
		Name        string
		Category    string
		Host        string
		Lines       []map[string]any
	}
	var got captured
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.ContentType = r.Header.Get("Content-Type")
		got.Name = r.Header.Get("X-Sumo-Name")
		got.Category = r.Header.Get("X-Sumo-Category")
		got.Host = r.Header.Get("X-Sumo-Host")
		scanner := bufio.NewScanner(r.Body)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal(line, &rec); err != nil {
				t.Fatalf("server decode: %v", err)
			}
			got.Lines = append(got.Lines, rec)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	e, err := New(Config{URL: ts.URL, Host: "host-a"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Shutdown(context.Background())

	if err := e.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{
		sampleSpan(t), sampleSpan(t),
	}); err != nil {
		t.Fatalf("ExportSpans: %v", err)
	}

	if got.ContentType != "application/json" {
		t.Errorf("Content-Type = %q", got.ContentType)
	}
	if got.Name != "helm-ai-kernel" {
		t.Errorf("X-Sumo-Name = %q", got.Name)
	}
	if got.Category != "helm/governance" {
		t.Errorf("X-Sumo-Category = %q", got.Category)
	}
	if got.Host != "host-a" {
		t.Errorf("X-Sumo-Host = %q", got.Host)
	}
	if len(got.Lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(got.Lines))
	}
	for _, line := range got.Lines {
		if line["event_type"] != "helm.governance" {
			t.Errorf("event_type = %v", line["event_type"])
		}
		if line["correlation_id"] != "corr-1" {
			t.Errorf("correlation_id = %v", line["correlation_id"])
		}
		genAI, ok := line["gen_ai"].(map[string]any)
		if !ok || genAI["system"] != "openai" {
			t.Errorf("gen_ai = %+v", line["gen_ai"])
		}
		helmFields, ok := line["helm"].(map[string]any)
		if !ok || helmFields["verdict"] != "ALLOW" {
			t.Errorf("helm = %+v", line["helm"])
		}
	}
}

func TestExportSpans_PropagatesServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer ts.Close()
	e, err := New(Config{URL: ts.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = e.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{sampleSpan(t)})
	if err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Errorf("expected 503 error, got %v", err)
	}
}

func TestExportSpans_NoSpansIsNoOp(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer ts.Close()
	e, _ := New(Config{URL: ts.URL})
	if err := e.ExportSpans(context.Background(), nil); err != nil {
		t.Errorf("ExportSpans nil: %v", err)
	}
	if called {
		t.Error("server should not be called for empty span batch")
	}
}
