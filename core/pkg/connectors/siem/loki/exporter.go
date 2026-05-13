// Package loki implements an OTel SpanExporter that translates helm-ai-kernel
// governance spans (carrying OTel GenAI semconv attributes plus the helm.*
// governance namespace) into Grafana Loki push events.
//
// Wire shape: each ReadOnlySpan becomes one entry in a Loki stream keyed by
// labels {service:"helm-ai-kernel", verdict:"<allow|deny|escalate>", policy_id,
// gen_ai_system}. The line value is a JSON-encoded copy of the full
// attribute bag plus span identifiers so Grafana queries can pivot on
// either gen_ai.* or helm.* without flattening loss.
//
// Reference: Grafana Loki HTTP API — https://grafana.com/docs/loki/latest/api/#push-log-entries-to-loki
package loki

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Config configures a Loki exporter.
type Config struct {
	// URL is the Loki push endpoint, e.g. "https://loki.example.com/loki/api/v1/push".
	URL string
	// TenantID is sent as the `X-Scope-OrgID` header. Optional - only
	// required when Loki is configured for multi-tenancy.
	TenantID string
	// BasicAuthUser, BasicAuthPass are optional HTTP Basic Auth credentials
	// (Grafana Cloud Loki commonly accepts user=instanceID, pass=apiKey).
	BasicAuthUser string
	BasicAuthPass string
	// ServiceLabel is the value emitted under the `service` Loki label;
	// defaults to "helm-ai-kernel".
	ServiceLabel string
	// HTTPClient is optional; defaults to a 10s-timeout client.
	HTTPClient *http.Client
}

// Exporter implements sdktrace.SpanExporter for Grafana Loki.
type Exporter struct {
	cfg  Config
	once sync.Once
	http *http.Client
}

// New constructs a Loki exporter. URL is required.
func New(cfg Config) (*Exporter, error) {
	if cfg.URL == "" {
		return nil, errors.New("loki: URL is required")
	}
	if cfg.ServiceLabel == "" {
		cfg.ServiceLabel = "helm-ai-kernel"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Exporter{cfg: cfg, http: hc}, nil
}

// pushPayload is Loki's `/loki/api/v1/push` request body shape.
type pushPayload struct {
	Streams []stream `json:"streams"`
}

type stream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

// ExportSpans translates each span to a Loki entry, groups entries by
// label set, and POSTs the batch as a single push payload.
func (e *Exporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if len(spans) == 0 {
		return nil
	}
	groups := map[string]*stream{}
	for _, s := range spans {
		labels := streamLabels(s, e.cfg)
		key := labelKey(labels)
		entry, err := translate(s)
		if err != nil {
			return err
		}
		if g, ok := groups[key]; ok {
			g.Values = append(g.Values, entry)
			continue
		}
		groups[key] = &stream{Stream: labels, Values: [][2]string{entry}}
	}

	out := pushPayload{Streams: make([]stream, 0, len(groups))}
	for _, g := range groups {
		out.Streams = append(out.Streams, *g)
	}

	body, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("loki: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("loki: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.cfg.TenantID != "" {
		req.Header.Set("X-Scope-OrgID", e.cfg.TenantID)
	}
	if e.cfg.BasicAuthUser != "" || e.cfg.BasicAuthPass != "" {
		req.SetBasicAuth(e.cfg.BasicAuthUser, e.cfg.BasicAuthPass)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return fmt.Errorf("loki: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("loki: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
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

// translate converts a ReadOnlySpan into a single Loki [timestamp, line]
// entry. Timestamp is unix-nanos as a string; line is JSON-encoded so
// Grafana's Loki query language can extract any field via `json` parser.
func translate(s sdktrace.ReadOnlySpan) ([2]string, error) {
	attrs := attrMap(s.Attributes())
	when := s.EndTime()
	if when.IsZero() {
		when = s.StartTime()
	}
	line := map[string]any{
		"event_type":     "helm.governance",
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
	raw, err := json.Marshal(line)
	if err != nil {
		return [2]string{}, fmt.Errorf("loki: marshal line: %w", err)
	}
	return [2]string{strconv.FormatInt(when.UnixNano(), 10), string(raw)}, nil
}

// streamLabels selects the Loki label set for a span. Labels MUST be low
// cardinality per Loki guidance: we limit to service, verdict, policy_id,
// and gen_ai_system (or empty when missing).
func streamLabels(s sdktrace.ReadOnlySpan, cfg Config) map[string]string {
	out := map[string]string{"service": cfg.ServiceLabel}
	for _, kv := range s.Attributes() {
		key := string(kv.Key)
		switch key {
		case observability.HelmVerdict:
			out["verdict"] = kv.Value.AsString()
		case observability.HelmPolicyID:
			out["policy_id"] = kv.Value.AsString()
		case observability.GenAISystem:
			out["gen_ai_system"] = kv.Value.AsString()
		}
	}
	return out
}

// labelKey returns a stable key for a label map by joining sorted entries.
func labelKey(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte(';')
	}
	return b.String()
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
