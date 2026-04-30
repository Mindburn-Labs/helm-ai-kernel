// Package splunk_hec implements an OTel SpanExporter that translates
// helm-oss governance spans (carrying OTel GenAI semconv attributes plus the
// helm.* governance namespace) into Splunk HTTP Event Collector (HEC) events.
//
// Wire shape: each ReadOnlySpan becomes one HEC event with `event.type =
// "helm.governance"`, retaining the gen_ai.* and helm.* attributes verbatim
// so Splunk searches can pivot on either vocabulary.
//
// Reference: Splunk HEC docs — https://docs.splunk.com/Documentation/Splunk/latest/Data/HECRESTendpoints
package splunk_hec

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

	"github.com/Mindburn-Labs/helm-oss/core/pkg/observability"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Config configures a Splunk HEC exporter.
type Config struct {
	// URL is the HEC endpoint, e.g. "https://splunk.example.com:8088/services/collector/event".
	URL string
	// Token is the HEC bearer token (sent as `Authorization: Splunk <token>`).
	Token string
	// Index optionally pins emitted events to a specific Splunk index.
	Index string
	// Source overrides Splunk's `source` field (default "helm-oss").
	Source string
	// SourceType overrides Splunk's `sourcetype` field (default "helm:governance").
	SourceType string
	// Host overrides Splunk's `host` field (default = OS hostname or empty).
	Host string
	// HTTPClient is optional; defaults to a 10s-timeout client.
	HTTPClient *http.Client
}

// Exporter implements sdktrace.SpanExporter for Splunk HEC.
type Exporter struct {
	cfg  Config
	once sync.Once
	http *http.Client
}

// New constructs a Splunk HEC exporter. URL and Token are required.
func New(cfg Config) (*Exporter, error) {
	if cfg.URL == "" {
		return nil, errors.New("splunk_hec: URL is required")
	}
	if cfg.Token == "" {
		return nil, errors.New("splunk_hec: Token is required")
	}
	if cfg.Source == "" {
		cfg.Source = "helm-oss"
	}
	if cfg.SourceType == "" {
		cfg.SourceType = "helm:governance"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Exporter{cfg: cfg, http: hc}, nil
}

// hecEvent is the on-the-wire shape Splunk HEC accepts on
// /services/collector/event.
type hecEvent struct {
	Time       float64        `json:"time"`
	Host       string         `json:"host,omitempty"`
	Source     string         `json:"source,omitempty"`
	SourceType string         `json:"sourcetype,omitempty"`
	Index      string         `json:"index,omitempty"`
	Event      map[string]any `json:"event"`
}

// ExportSpans translates each span to a Splunk HEC event and POSTs the batch
// as newline-delimited JSON, the format Splunk HEC accepts for batched events.
func (e *Exporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if len(spans) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, s := range spans {
		ev := translate(s, e.cfg)
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("splunk_hec: encode: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.URL, &buf)
	if err != nil {
		return fmt.Errorf("splunk_hec: build request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+e.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.http.Do(req)
	if err != nil {
		return fmt.Errorf("splunk_hec: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("splunk_hec: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Shutdown is a no-op; the exporter holds no long-lived resources.
func (e *Exporter) Shutdown(ctx context.Context) error {
	e.once.Do(func() {
		if t, ok := e.http.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	})
	return nil
}

// translate maps a ReadOnlySpan into the HEC event shape. The full attribute
// bag is passed through under `event.attributes` so Splunk searches can pivot
// on `gen_ai.*` or `helm.*` keys without flattening loss.
func translate(s sdktrace.ReadOnlySpan, cfg Config) hecEvent {
	attrs := attrMap(s.Attributes())
	event := map[string]any{
		"event.type":     "helm.governance",
		"name":           s.Name(),
		"trace_id":       s.SpanContext().TraceID().String(),
		"span_id":        s.SpanContext().SpanID().String(),
		"start_time":     s.StartTime().UTC().Format(time.RFC3339Nano),
		"end_time":       s.EndTime().UTC().Format(time.RFC3339Nano),
		"duration_ns":    s.EndTime().Sub(s.StartTime()).Nanoseconds(),
		"attributes":     attrs,
		"gen_ai":         subset(attrs, "gen_ai."),
		"helm":           subset(attrs, "helm."),
		"verdict":        attrs[observability.HelmVerdict],
		"correlation_id": attrs[observability.HelmCorrelationID],
		"tool_call_id":   attrs[observability.GenAIToolCallID],
	}
	when := s.EndTime()
	if when.IsZero() {
		when = s.StartTime()
	}
	return hecEvent{
		Time:       float64(when.UnixNano()) / 1e9,
		Host:       cfg.Host,
		Source:     cfg.Source,
		SourceType: cfg.SourceType,
		Index:      cfg.Index,
		Event:      event,
	}
}

// attrMap collapses an OTel attribute slice into a stringly-typed map. This
// preserves the OTel value semantics by deferring to attribute.Value.AsInterface,
// which returns native Go types (bool, int64, float64, string, slice).
func attrMap(kvs []attribute.KeyValue) map[string]any {
	out := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		out[string(kv.Key)] = kv.Value.AsInterface()
	}
	return out
}

// subset returns every entry in m whose key starts with prefix, with the
// prefix stripped. Keeps the SIEM event compact and queryable.
func subset(m map[string]any, prefix string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if strings.HasPrefix(k, prefix) {
			out[strings.TrimPrefix(k, prefix)] = v
		}
	}
	return out
}
