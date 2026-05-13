package splunk_hec

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
			attribute.String(observability.HelmProofNodeID, "pg-99"),
			attribute.String(observability.HelmCorrelationID, "corr-1"),
		},
	}
	return stub.Snapshot()
}

func TestExportSpans_ProducesHECEventBatch(t *testing.T) {
	var seen []map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Splunk tok-1" {
			t.Errorf("authorization header = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			if line == "" {
				continue
			}
			var ev map[string]any
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("decode HEC line: %v", err)
			}
			seen = append(seen, ev)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	exp, err := New(Config{URL: ts.URL, Token: "tok-1", Index: "main"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := exp.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{sampleSpan(t)}); err != nil {
		t.Fatalf("ExportSpans: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("expected 1 HEC event, got %d", len(seen))
	}
	ev := seen[0]
	if got, _ := ev["index"].(string); got != "main" {
		t.Errorf("index = %q", got)
	}
	body, _ := ev["event"].(map[string]any)
	if body["event.type"] != "helm.governance" {
		t.Errorf("event.type = %v", body["event.type"])
	}
	if body["verdict"] != "ALLOW" {
		t.Errorf("verdict = %v", body["verdict"])
	}
	gen, _ := body["gen_ai"].(map[string]any)
	if gen["request.model"] != "gpt-4o" {
		t.Errorf("gen_ai.request.model = %v", gen["request.model"])
	}
	helm, _ := body["helm"].(map[string]any)
	if helm["policy_id"] != "bundle/rule-1" {
		t.Errorf("helm.policy_id = %v", helm["policy_id"])
	}
}

func TestExportSpans_PropagatesNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer ts.Close()
	exp, _ := New(Config{URL: ts.URL, Token: "tok"})
	err := exp.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{sampleSpan(t)})
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500 error, got %v", err)
	}
}

func TestNew_ValidatesRequiredFields(t *testing.T) {
	if _, err := New(Config{Token: "x"}); err == nil {
		t.Fatal("expected URL required error")
	}
	if _, err := New(Config{URL: "https://x"}); err == nil {
		t.Fatal("expected Token required error")
	}
}

func TestExportSpans_NoOpOnEmpty(t *testing.T) {
	exp, _ := New(Config{URL: "https://unused", Token: "x"})
	if err := exp.ExportSpans(context.Background(), nil); err != nil {
		t.Fatalf("expected no-op nil-error, got %v", err)
	}
}

func TestShutdown(t *testing.T) {
	exp, _ := New(Config{URL: "https://unused", Token: "x"})
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}
