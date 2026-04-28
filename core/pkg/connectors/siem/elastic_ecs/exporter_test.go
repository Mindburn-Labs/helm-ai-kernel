package elastic_ecs

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/observability"
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
			attribute.String(observability.GenAISystem, "openai"),
			attribute.String(observability.GenAIRequestModel, "gpt-4o"),
			attribute.String(observability.GenAIToolName, "search_web"),
			attribute.String(observability.GenAIToolCallID, "corr-1"),
			attribute.String(observability.HelmVerdict, verdict),
			attribute.String(observability.HelmPolicyID, "bundle/rule-1"),
			attribute.String(observability.HelmCorrelationID, "corr-1"),
		},
	}
	return stub.Snapshot()
}

func TestExportSpans_ProducesECSBulk(t *testing.T) {
	var actions []map[string]any
	var docs []map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "ApiKey api-key-1" {
			t.Errorf("authorization = %q", got)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-ndjson" {
			t.Errorf("Content-Type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		for i, line := range lines {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				t.Fatalf("decode line %d: %v", i, err)
			}
			if i%2 == 0 {
				actions = append(actions, obj)
			} else {
				docs = append(docs, obj)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":false,"items":[]}`))
	}))
	defer ts.Close()

	exp, err := New(Config{URL: ts.URL, Index: "helm-governance", APIKey: "api-key-1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := exp.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{
		sampleSpan(t, "ALLOW"),
		sampleSpan(t, "DENY"),
	}); err != nil {
		t.Fatalf("ExportSpans: %v", err)
	}
	if len(actions) != 2 || len(docs) != 2 {
		t.Fatalf("expected 2 actions/2 docs, got %d/%d", len(actions), len(docs))
	}
	idx, _ := actions[0]["index"].(map[string]any)
	if idx["_index"] != "helm-governance" {
		t.Errorf("_index = %v", idx["_index"])
	}
	allowDoc := docs[0]
	ev, _ := allowDoc["event"].(map[string]any)
	if ev["dataset"] != "helm.governance" {
		t.Errorf("event.dataset = %v", ev["dataset"])
	}
	if ev["outcome"] != "success" {
		t.Errorf("ALLOW outcome = %v", ev["outcome"])
	}
	denyDoc := docs[1]
	ev2, _ := denyDoc["event"].(map[string]any)
	if ev2["outcome"] != "failure" {
		t.Errorf("DENY outcome = %v", ev2["outcome"])
	}
	gen, _ := allowDoc["gen_ai"].(map[string]any)
	if gen["request.model"] != "gpt-4o" {
		t.Errorf("gen_ai.request.model = %v", gen["request.model"])
	}
}

func TestExportSpans_BulkPartialErrorsSurface(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":true,"items":[{"index":{"error":{"reason":"x"}}}]}`))
	}))
	defer ts.Close()
	exp, _ := New(Config{URL: ts.URL, Index: "x"})
	err := exp.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{sampleSpan(t, "ALLOW")})
	if err == nil || !strings.Contains(err.Error(), "partial errors") {
		t.Fatalf("expected partial errors, got %v", err)
	}
}

func TestNew_RequiredFields(t *testing.T) {
	if _, err := New(Config{Index: "x"}); err == nil {
		t.Fatal("expected URL required")
	}
	if _, err := New(Config{URL: "https://x"}); err == nil {
		t.Fatal("expected Index required")
	}
}

func TestExportSpans_BasicAuthFallback(t *testing.T) {
	var sawAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"errors":false}`))
	}))
	defer ts.Close()
	exp, _ := New(Config{URL: ts.URL, Index: "x", Username: "u", Password: "p"})
	if err := exp.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{sampleSpan(t, "ALLOW")}); err != nil {
		t.Fatalf("ExportSpans: %v", err)
	}
	if !strings.HasPrefix(sawAuth, "Basic ") {
		t.Errorf("expected Basic auth header, got %q", sawAuth)
	}
}

func TestExportSpans_NoOpOnEmpty(t *testing.T) {
	exp, _ := New(Config{URL: "https://x", Index: "x"})
	if err := exp.ExportSpans(context.Background(), nil); err != nil {
		t.Fatalf("expected nil for empty, got %v", err)
	}
}

func TestShutdown(t *testing.T) {
	exp, _ := New(Config{URL: "https://x", Index: "x"})
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}
