// Package datadog_logs implements an OTel SpanExporter that translates
// helm-oss governance spans into Datadog Logs Intake events posted to
// /api/v2/logs.
//
// Wire shape: each ReadOnlySpan becomes one Datadog log entry with
// `ddsource = helm-oss`, `service = helm-governance`, structured
// attributes mirroring the OTel GenAI semconv keys (gen_ai.*) and the
// helm.* governance namespace.
//
// Reference: https://docs.datadoghq.com/api/latest/logs/#send-logs
package datadog_logs

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

// Config configures a Datadog Logs exporter.
type Config struct {
	// Site is the Datadog site, e.g. "datadoghq.com", "datadoghq.eu",
	// "us3.datadoghq.com", "ddog-gov.com". When set, the URL is derived as
	// "https://http-intake.logs.<Site>/api/v2/logs". Mutually exclusive with URL.
	Site string
	// URL overrides the intake endpoint. If unset, derived from Site.
	URL string
	// APIKey is the Datadog API key (sent as `DD-API-KEY`).
	APIKey string
	// Service overrides the `service` tag (default "helm-governance").
	Service string
	// Source overrides the `ddsource` tag (default "helm-oss").
	Source string
	// Hostname is sent as `hostname` (default "" — Datadog will infer).
	Hostname string
	// Env populates the `env` tag (e.g. "prod", "staging").
	Env string
	// HTTPClient is optional; defaults to a 10s-timeout client.
	HTTPClient *http.Client
}

// Exporter implements sdktrace.SpanExporter for Datadog Logs.
type Exporter struct {
	cfg  Config
	url  string
	http *http.Client
}

// New constructs a Datadog Logs exporter. APIKey is required and either
// Site or URL must be set.
func New(cfg Config) (*Exporter, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("datadog_logs: APIKey is required")
	}
	url := strings.TrimSpace(cfg.URL)
	if url == "" {
		if cfg.Site == "" {
			return nil, errors.New("datadog_logs: Site or URL is required")
		}
		url = "https://http-intake.logs." + strings.TrimPrefix(cfg.Site, "https://") + "/api/v2/logs"
	}
	if cfg.Service == "" {
		cfg.Service = "helm-governance"
	}
	if cfg.Source == "" {
		cfg.Source = "helm-oss"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Exporter{cfg: cfg, url: url, http: hc}, nil
}

// ddLog mirrors the Datadog Logs Intake JSON shape.
type ddLog struct {
	Source     string         `json:"ddsource"`
	Tags       string         `json:"ddtags,omitempty"`
	Hostname   string         `json:"hostname,omitempty"`
	Service    string         `json:"service"`
	Message    string         `json:"message"`
	Status     string         `json:"status,omitempty"`
	Attributes map[string]any `json:"attributes"`
}

// ExportSpans posts the batch as a JSON array to Datadog Logs Intake.
func (e *Exporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if len(spans) == 0 {
		return nil
	}
	logs := make([]ddLog, 0, len(spans))
	for _, s := range spans {
		logs = append(logs, translate(s, e.cfg))
	}
	body, err := json.Marshal(logs)
	if err != nil {
		return fmt.Errorf("datadog_logs: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("datadog_logs: build request: %w", err)
	}
	req.Header.Set("DD-API-KEY", e.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.http.Do(req)
	if err != nil {
		return fmt.Errorf("datadog_logs: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("datadog_logs: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// Shutdown is a no-op; the exporter holds no long-lived resources.
func (e *Exporter) Shutdown(ctx context.Context) error { return nil }

func translate(s sdktrace.ReadOnlySpan, cfg Config) ddLog {
	attrs := attrMap(s.Attributes())
	verdict, _ := attrs[observability.HelmVerdict].(string)
	status := "info"
	switch verdict {
	case "DENY":
		status = "error"
	case "ESCALATE":
		status = "warn"
	}
	tags := []string{
		"verdict:" + nonEmpty(verdict, "unknown"),
		"helm.policy_id:" + nonEmpty(asString(attrs[observability.HelmPolicyID]), "none"),
	}
	if cfg.Env != "" {
		tags = append(tags, "env:"+cfg.Env)
	}
	if v := asString(attrs[observability.GenAISystem]); v != "" {
		tags = append(tags, "gen_ai.system:"+v)
	}
	if v := asString(attrs[observability.GenAIRequestModel]); v != "" {
		tags = append(tags, "gen_ai.request.model:"+v)
	}
	body := map[string]any{
		"event.type":     "helm.governance",
		"name":           s.Name(),
		"trace_id":       s.SpanContext().TraceID().String(),
		"span_id":        s.SpanContext().SpanID().String(),
		"start_time":     s.StartTime().UTC().Format(time.RFC3339Nano),
		"end_time":       s.EndTime().UTC().Format(time.RFC3339Nano),
		"duration_ns":    s.EndTime().Sub(s.StartTime()).Nanoseconds(),
		"otel.span":      attrs,
		"gen_ai":         subset(attrs, "gen_ai."),
		"helm":           subset(attrs, "helm."),
		"correlation_id": attrs[observability.HelmCorrelationID],
	}
	return ddLog{
		Source:     cfg.Source,
		Tags:       strings.Join(tags, ","),
		Hostname:   cfg.Hostname,
		Service:    cfg.Service,
		Status:     status,
		Message:    fmt.Sprintf("helm.governance verdict=%s tool=%s", nonEmpty(verdict, "UNKNOWN"), asString(attrs[observability.GenAIToolName])),
		Attributes: body,
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
