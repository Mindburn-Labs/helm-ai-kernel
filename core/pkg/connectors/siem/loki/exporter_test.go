package loki

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

func sampleSpan(t *testing.T, verdict, policyID string) sdktrace.ReadOnlySpan {
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
			attribute.String(observability.HelmVerdict, verdict),
			attribute.String(observability.HelmPolicyID, policyID),
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

func TestNew_DefaultsServiceLabel(t *testing.T) {
	e, err := New(Config{URL: "http://example/loki/api/v1/push"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.cfg.ServiceLabel != "helm-ai-kernel" {
		t.Errorf("ServiceLabel default = %q, want %q", e.cfg.ServiceLabel, "helm-ai-kernel")
	}
}

func TestExportSpans_ProducesPushPayload(t *testing.T) {
	var captured pushPayload
	var capturedTenant string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = r.Header.Get("X-Scope-OrgID")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("server decode: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	e, err := New(Config{URL: ts.URL, TenantID: "tenant-alpha"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Shutdown(context.Background())

	if err := e.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{
		sampleSpan(t, "ALLOW", "bundle/rule-1"),
		sampleSpan(t, "ALLOW", "bundle/rule-1"),
		sampleSpan(t, "DENY", "bundle/rule-2"),
	}); err != nil {
		t.Fatalf("ExportSpans: %v", err)
	}

	if capturedTenant != "tenant-alpha" {
		t.Errorf("tenant header = %q, want tenant-alpha", capturedTenant)
	}
	if len(captured.Streams) != 2 {
		t.Fatalf("streams = %d, want 2 (one per (verdict,policy) label set)", len(captured.Streams))
	}

	for _, s := range captured.Streams {
		if s.Stream["service"] != "helm-ai-kernel" {
			t.Errorf("stream service label = %q", s.Stream["service"])
		}
		if s.Stream["gen_ai_system"] != "openai" {
			t.Errorf("stream gen_ai_system label = %q", s.Stream["gen_ai_system"])
		}
		for _, entry := range s.Values {
			if len(entry) != 2 {
				t.Fatalf("entry len = %d, want 2", len(entry))
			}
			var line map[string]any
			if err := json.Unmarshal([]byte(entry[1]), &line); err != nil {
				t.Fatalf("entry json: %v", err)
			}
			if line["event_type"] != "helm.governance" {
				t.Errorf("event_type = %v, want helm.governance", line["event_type"])
			}
			if line["correlation_id"] != "corr-1" {
				t.Errorf("correlation_id = %v", line["correlation_id"])
			}
			if line["tool_call_id"] != "corr-1" {
				t.Errorf("tool_call_id = %v", line["tool_call_id"])
			}
			helmSubset, ok := line["helm"].(map[string]any)
			if !ok || helmSubset["verdict"] == nil {
				t.Errorf("helm subset missing or malformed: %+v", line["helm"])
			}
			genAI, ok := line["gen_ai"].(map[string]any)
			if !ok || genAI["system"] != "openai" {
				t.Errorf("gen_ai subset = %+v", line["gen_ai"])
			}
		}
	}
}

func TestExportSpans_PropagatesServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "back off", http.StatusTooManyRequests)
	}))
	defer ts.Close()

	e, err := New(Config{URL: ts.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = e.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{sampleSpan(t, "ALLOW", "p1")})
	if err == nil || !strings.Contains(err.Error(), "status 429") {
		t.Errorf("expected 429 error, got %v", err)
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
