package tracing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// LangSmithExporter exports HELM spans to LangSmith for LLM observability.
//
// Spans are mapped to LangSmith "runs" using the v1 ingest API.
// See https://docs.smith.langchain.com/ for API details.
type LangSmithExporter struct {
	apiKey   string
	endpoint string
	client   *http.Client
}

// NewLangSmithExporter creates a new LangSmithExporter.
//
//	e := tracing.NewLangSmithExporter(apiKey, "https://api.smith.langchain.com")
func NewLangSmithExporter(apiKey, endpoint string) *LangSmithExporter {
	return &LangSmithExporter{
		apiKey:   apiKey,
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// langsmithRun is the wire format for a LangSmith run ingestion request.
type langsmithRun struct {
	ID          string            `json:"id"`
	TraceID     string            `json:"trace_id"`
	ParentRunID string            `json:"parent_run_id,omitempty"`
	Name        string            `json:"name"`
	RunType     string            `json:"run_type"`   // "chain", "tool", "llm", …
	StartTime   string            `json:"start_time"` // ISO-8601
	EndTime     string            `json:"end_time,omitempty"`
	Status      string            `json:"status"` // "success" | "error"
	Extra       map[string]string `json:"extra,omitempty"`
}

// Export serialises spans and POSTs them to the LangSmith runs endpoint.
func (e *LangSmithExporter) Export(ctx context.Context, spans []Span) error {
	if len(spans) == 0 {
		return nil
	}

	runs := make([]langsmithRun, len(spans))
	for i, s := range spans {
		runs[i] = spanToLangSmithRun(s)
	}

	payload, err := json.Marshal(runs)
	if err != nil {
		return fmt.Errorf("langsmith: marshal runs: %w", err)
	}

	url := e.endpoint + "/runs/batch"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("langsmith: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", e.apiKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("langsmith: POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("langsmith: unexpected status %d from %s", resp.StatusCode, url)
	}

	return nil
}

// spanToLangSmithRun converts a HELM Span to the LangSmith run wire format.
func spanToLangSmithRun(s Span) langsmithRun {
	status := "success"
	if s.Status == StatusError {
		status = "error"
	}

	run := langsmithRun{
		ID:      string(s.SpanID),
		TraceID: string(s.TraceID),
		Name:    s.Name,
		RunType: "chain",
		Status:  status,
		Extra:   s.Attributes,
	}

	if s.ParentID != "" {
		run.ParentRunID = string(s.ParentID)
	}

	if s.StartTimeMs > 0 {
		run.StartTime = msToISO(s.StartTimeMs)
	}
	if s.EndTimeMs > 0 {
		run.EndTime = msToISO(s.EndTimeMs)
	}

	return run
}

// msToISO converts a Unix-millisecond timestamp to an ISO-8601 string.
func msToISO(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
}
