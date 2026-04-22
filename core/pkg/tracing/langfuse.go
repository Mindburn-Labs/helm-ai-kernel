package tracing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// LangfuseExporter exports HELM spans to Langfuse for LLM observability.
//
// Spans are mapped to Langfuse "spans" within a trace using the public
// ingestion API (/api/public/ingestion). Authentication uses HTTP Basic Auth
// with the public key as the username and the secret key as the password.
type LangfuseExporter struct {
	publicKey string
	secretKey string
	endpoint  string
	client    *http.Client
}

// NewLangfuseExporter creates a new LangfuseExporter.
//
//	e := tracing.NewLangfuseExporter(publicKey, secretKey, "https://cloud.langfuse.com")
func NewLangfuseExporter(publicKey, secretKey, endpoint string) *LangfuseExporter {
	return &LangfuseExporter{
		publicKey: publicKey,
		secretKey: secretKey,
		endpoint:  endpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// langfuseBatch is the top-level ingestion payload.
type langfuseBatch struct {
	Batch []langfuseEvent `json:"batch"`
}

// langfuseEvent wraps a single ingestion event.
type langfuseEvent struct {
	ID        string          `json:"id"`
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"` // "span-create"
	Body      langfuseSpanBody `json:"body"`
}

// langfuseSpanBody carries the span payload.
type langfuseSpanBody struct {
	ID         string            `json:"id"`
	TraceID    string            `json:"traceId"`
	ParentID   string            `json:"parentObservationId,omitempty"`
	Name       string            `json:"name"`
	StartTime  string            `json:"startTime"`
	EndTime    string            `json:"endTime,omitempty"`
	StatusCode string            `json:"statusCode,omitempty"` // "OK" | "ERROR"
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Export serialises spans and POSTs them to the Langfuse ingestion endpoint.
func (e *LangfuseExporter) Export(ctx context.Context, spans []Span) error {
	if len(spans) == 0 {
		return nil
	}

	events := make([]langfuseEvent, len(spans))
	for i, s := range spans {
		events[i] = spanToLangfuseEvent(s)
	}

	batch := langfuseBatch{Batch: events}
	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("langfuse: marshal batch: %w", err)
	}

	url := e.endpoint + "/api/public/ingestion"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("langfuse: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+e.basicAuth())

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("langfuse: POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("langfuse: unexpected status %d from %s", resp.StatusCode, url)
	}

	return nil
}

// basicAuth encodes the public/secret key pair as HTTP Basic Auth credentials.
func (e *LangfuseExporter) basicAuth() string {
	return base64.StdEncoding.EncodeToString([]byte(e.publicKey + ":" + e.secretKey))
}

// spanToLangfuseEvent converts a HELM Span to the Langfuse ingestion wire format.
func spanToLangfuseEvent(s Span) langfuseEvent {
	body := langfuseSpanBody{
		ID:       string(s.SpanID),
		TraceID:  string(s.TraceID),
		Name:     s.Name,
		Metadata: s.Attributes,
	}

	if s.ParentID != "" {
		body.ParentID = string(s.ParentID)
	}

	if s.StartTimeMs > 0 {
		body.StartTime = msToISO(s.StartTimeMs)
	}
	if s.EndTimeMs > 0 {
		body.EndTime = msToISO(s.EndTimeMs)
	}

	switch s.Status {
	case StatusError:
		body.StatusCode = "ERROR"
	default:
		body.StatusCode = "OK"
	}

	return langfuseEvent{
		ID:        string(s.SpanID) + "-evt",
		Timestamp: msToISO(s.StartTimeMs),
		Type:      "span-create",
		Body:      body,
	}
}
