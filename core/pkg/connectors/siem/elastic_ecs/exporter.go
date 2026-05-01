// Package elastic_ecs implements an OTel SpanExporter that translates
// helm-oss governance spans into ECS-shaped documents posted to the
// Elasticsearch _bulk API.
//
// Wire shape: each ReadOnlySpan becomes one ECS document with `@timestamp`,
// `event.dataset = "helm.governance"`, `event.outcome` mapped from
// helm.verdict, plus the OTel GenAI semconv keys (gen_ai.*) and the helm.*
// governance namespace preserved verbatim.
//
// Reference: ECS — https://www.elastic.co/guide/en/ecs/current/
//
//	Bulk API — https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
package elastic_ecs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/observability"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Config configures an Elasticsearch ECS exporter.
type Config struct {
	// URL is the Elasticsearch base URL, e.g. "https://es.example.com:9200".
	// The exporter posts to "<URL>/_bulk".
	URL string
	// Index is the destination index, e.g. "helm-governance".
	Index string
	// APIKey is an Elasticsearch API key. Sent as `Authorization: ApiKey <key>`.
	// Mutually exclusive with Username/Password.
	APIKey string
	// Username/Password enable HTTP Basic auth as an alternative to APIKey.
	Username string
	Password string
	// ServiceName overrides ECS `service.name` (default "helm-governance").
	ServiceName string
	// HTTPClient is optional; defaults to a 10s-timeout client.
	HTTPClient *http.Client
}

// Exporter implements sdktrace.SpanExporter for Elasticsearch ECS.
type Exporter struct {
	cfg  Config
	http *http.Client
}

// New constructs an Elasticsearch ECS exporter. URL and Index are required.
func New(cfg Config) (*Exporter, error) {
	if cfg.URL == "" {
		return nil, errors.New("elastic_ecs: URL is required")
	}
	if cfg.Index == "" {
		return nil, errors.New("elastic_ecs: Index is required")
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "helm-governance"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Exporter{cfg: cfg, http: hc}, nil
}

// ExportSpans posts the batch as Elasticsearch _bulk NDJSON.
func (e *Exporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if len(spans) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, s := range spans {
		// _bulk action line.
		action := map[string]any{"index": map[string]any{"_index": e.cfg.Index}}
		if err := json.NewEncoder(&buf).Encode(action); err != nil {
			return fmt.Errorf("elastic_ecs: encode action: %w", err)
		}
		// Document line.
		doc := translate(s, e.cfg)
		if err := json.NewEncoder(&buf).Encode(doc); err != nil {
			return fmt.Errorf("elastic_ecs: encode doc: %w", err)
		}
	}
	url := strings.TrimRight(e.cfg.URL, "/") + "/_bulk"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return fmt.Errorf("elastic_ecs: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	switch {
	case e.cfg.APIKey != "":
		req.Header.Set("Authorization", "ApiKey "+e.cfg.APIKey)
	case e.cfg.Username != "":
		req.SetBasicAuth(e.cfg.Username, e.cfg.Password)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return fmt.Errorf("elastic_ecs: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("elastic_ecs: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// Elasticsearch _bulk returns 200 even on per-document errors; surface them.
	var br bulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&br); err == nil && br.Errors {
		return fmt.Errorf("elastic_ecs: bulk reported partial errors")
	}
	return nil
}

// Shutdown is a no-op.
func (e *Exporter) Shutdown(ctx context.Context) error { return nil }

type bulkResponse struct {
	Errors bool `json:"errors"`
}

// translate produces an ECS-shaped document from a span.
func translate(s sdktrace.ReadOnlySpan, cfg Config) map[string]any {
	attrs := attrMap(s.Attributes())
	verdict, _ := attrs[observability.HelmVerdict].(string)
	outcome := "unknown"
	switch verdict {
	case "ALLOW":
		outcome = "success"
	case "DENY":
		outcome = "failure"
	case "ESCALATE":
		outcome = "unknown"
	}
	when := s.EndTime()
	if when.IsZero() {
		when = s.StartTime()
	}
	doc := map[string]any{
		"@timestamp": when.UTC().Format(time.RFC3339Nano),
		"event": map[string]any{
			"dataset":  "helm.governance",
			"category": []string{"iam", "configuration"},
			"action":   "governance.decision",
			"outcome":  outcome,
			"duration": s.EndTime().Sub(s.StartTime()).Nanoseconds(),
		},
		"service": map[string]any{
			"name": cfg.ServiceName,
		},
		"trace": map[string]any{
			"id": s.SpanContext().TraceID().String(),
		},
		"span": map[string]any{
			"id":   s.SpanContext().SpanID().String(),
			"name": s.Name(),
		},
		"labels": map[string]any{
			"verdict":        verdict,
			"correlation_id": attrs[observability.HelmCorrelationID],
		},
		"gen_ai":  subset(attrs, "gen_ai."),
		"helm":    subset(attrs, "helm."),
		"message": fmt.Sprintf("helm.governance verdict=%s tool=%s", nonEmpty(verdict, "UNKNOWN"), asString(attrs[observability.GenAIToolName])),
	}
	return doc
}

func attrMap(kvs []attribute.KeyValue) map[string]any {
	out := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		out[string(kv.Key)] = kv.Value.AsInterface()
	}
	return out
}

func subset(m map[string]any, prefix string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if strings.HasPrefix(k, prefix) {
			out[strings.TrimPrefix(k, prefix)] = v
		}
	}
	return out
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
