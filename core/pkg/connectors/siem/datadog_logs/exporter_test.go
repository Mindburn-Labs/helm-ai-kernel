package datadog_logs

import (
	"context"
	"encoding/json"
	"io"
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

func sampleSpan(t *testing.T, verdict string) sdktrace.ReadOnlySpan {
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
			attribute.String(observability.GenAISystem, "anthropic"),
			attribute.String(observability.GenAIRequestModel, "claude-3-5-sonnet"),
			attribute.String(observability.GenAIToolName, "search_web"),
			attribute.String(observability.GenAIToolCallID, "corr-1"),
			attribute.String(observability.HelmVerdict, verdict),
			attribute.String(observability.HelmPolicyID, "bundle/rule-1"),
			attribute.String(observability.HelmCorrelationID, "corr-1"),
		},
	}
	return stub.Snapshot()
}

func TestExportSpans_ProducesDatadogLogs(t *testing.T) {
	var got []ddLog
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DD-API-KEY") != "key-1" {
			t.Errorf("DD-API-KEY = %q", r.Header.Get("DD-API-KEY"))
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	exp, err := New(Config{URL: ts.URL, APIKey: "key-1", Env: "staging"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := exp.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{sampleSpan(t, "DENY")}); err != nil {
		t.Fatalf("ExportSpans: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 log, got %d", len(got))
	}
	log := got[0]
	if log.Source != "helm-ai-kernel" {
		t.Errorf("ddsource = %q", log.Source)
	}
	if log.Service != "helm-governance" {
		t.Errorf("service = %q", log.Service)
	}
	if log.Status != "error" {
		t.Errorf("DENY verdict should map to error status, got %q", log.Status)
	}
	if !strings.Contains(log.Tags, "verdict:DENY") {
		t.Errorf("tags missing verdict: %s", log.Tags)
	}
	if !strings.Contains(log.Tags, "env:staging") {
		t.Errorf("tags missing env: %s", log.Tags)
	}
	if !strings.Contains(log.Tags, "gen_ai.system:anthropic") {
		t.Errorf("tags missing gen_ai.system: %s", log.Tags)
	}
	gen, _ := log.Attributes["gen_ai"].(map[string]any)
	if gen["request.model"] != "claude-3-5-sonnet" {
		t.Errorf("gen_ai.request.model = %v", gen["request.model"])
	}
}

func TestSiteDerivesURL(t *testing.T) {
	exp, err := New(Config{Site: "datadoghq.eu", APIKey: "x"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := "https://http-intake.logs.datadoghq.eu/api/v2/logs"
	if exp.url != want {
		t.Errorf("url = %q, want %q", exp.url, want)
	}
}

func TestNew_RequiredFields(t *testing.T) {
	if _, err := New(Config{Site: "datadoghq.com"}); err == nil {
		t.Fatal("expected APIKey required")
	}
	if _, err := New(Config{APIKey: "x"}); err == nil {
		t.Fatal("expected Site or URL required")
	}
}

func TestExportSpans_PropagatesNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate-limited", http.StatusTooManyRequests)
	}))
	defer ts.Close()
	exp, _ := New(Config{URL: ts.URL, APIKey: "k"})
	err := exp.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{sampleSpan(t, "ALLOW")})
	if err == nil || !strings.Contains(err.Error(), "status 429") {
		t.Fatalf("expected 429, got %v", err)
	}
}

func TestExportSpans_NoOpOnEmpty(t *testing.T) {
	exp, _ := New(Config{URL: "https://x", APIKey: "k"})
	if err := exp.ExportSpans(context.Background(), nil); err != nil {
		t.Fatalf("expected nil for empty batch, got %v", err)
	}
}

func TestShutdown(t *testing.T) {
	exp, _ := New(Config{URL: "https://x", APIKey: "k"})
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}
