// Package sumo implements an OTel SpanExporter that translates helm-ai-kernel
// governance spans (carrying OTel GenAI semconv attributes plus the helm.*
// governance namespace) into Sumo Logic HTTP source events.
//
// Wire shape: each ReadOnlySpan becomes one newline-delimited JSON record
// posted to a Sumo Logic HTTP source URL. The source URL itself encodes
// the collector + source identity; metadata is conveyed via X-Sumo-Name,
// X-Sumo-Category, X-Sumo-Host headers per the public Sumo HTTP source
// spec.
//
// Reference: https://help.sumologic.com/docs/send-data/hosted-collectors/http-source/
package sumo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Config configures a Sumo Logic exporter.
type Config struct {
	// URL is the Sumo Logic HTTP source endpoint, e.g.
	// "https://endpoint.collection.sumologic.com/receiver/v1/http/<token>".
	URL string
	// Name is sent as `X-Sumo-Name` (default "helm-ai-kernel").
	Name string
	// Category is sent as `X-Sumo-Category` (default "helm/governance").
	Category string
	// Host is sent as `X-Sumo-Host`.
	Host string
	// HTTPClient is optional; defaults to a 10s-timeout client.
	HTTPClient *http.Client
}

// Exporter implements sdktrace.SpanExporter for Sumo Logic.
type Exporter struct {
	cfg  Config
	once sync.Once
	http *http.Client
}

// New constructs a Sumo Logic exporter. URL is required.
func New(cfg Config) (*Exporter, error) {
	if cfg.URL == "" {
		return nil, errors.New("sumo: URL is required")
	}
	if cfg.Name == "" {
		cfg.Name = "helm-ai-kernel"
	}
	if cfg.Category == "" {
		cfg.Category = "helm/governance"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Exporter{cfg: cfg, http: hc}, nil
}

// ExportSpans translates each span into a JSON record and posts the
// batch as newline-delimited JSON. Sumo Logic recognises this shape
// natively and parses each line as a separate event.
func (e *Exporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if len(spans) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, s := range spans {
		rec := translate(s)
		if err := enc.Encode(rec); err != nil {
			return fmt.Errorf("sumo: encode: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.URL, &buf)
	if err != nil {
		return fmt.Errorf("sumo: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sumo-Name", e.cfg.Name)
	req.Header.Set("X-Sumo-Category", e.cfg.Category)
	if e.cfg.Host != "" {
		req.Header.Set("X-Sumo-Host", e.cfg.Host)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return fmt.Errorf("sumo: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("sumo: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

// Shutdown closes idle HTTP connections.
func (e *Exporter) Shutdown(ctx context.Context) error {
	e.once.Do(func() {
		if t, ok := e.http.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	})
	return nil
}

// translate maps a ReadOnlySpan into the Sumo Logic event shape. Same
// mapping as splunk_hec / loki so dashboards across backends pivot on
// identical helm.* / gen_ai.* keys.
func translate(s sdktrace.ReadOnlySpan) map[string]any {
	attrs := attrMap(s.Attributes())
	when := s.EndTime()
	if when.IsZero() {
		when = s.StartTime()
	}
	return map[string]any{
		"event_type":     "helm.governance",
		"name":           s.Name(),
		"trace_id":       s.SpanContext().TraceID().String(),
		"span_id":        s.SpanContext().SpanID().String(),
		"start_time":     s.StartTime().UTC().Format(time.RFC3339Nano),
		"end_time":       s.EndTime().UTC().Format(time.RFC3339Nano),
		"duration_ns":    s.EndTime().Sub(s.StartTime()).Nanoseconds(),
		"timestamp":      when.UTC().Format(time.RFC3339Nano),
		"attributes":     attrs,
		"gen_ai":         subset(attrs, "gen_ai."),
		"helm":           subset(attrs, "helm."),
		"verdict":        attrs[observability.HelmVerdict],
		"correlation_id": attrs[observability.HelmCorrelationID],
		"tool_call_id":   attrs[observability.GenAIToolCallID],
	}
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
