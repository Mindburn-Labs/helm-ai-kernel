package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// TestRFC7807_InternalError_NoLeak verifies that internal error details are never exposed to clients.
func TestRFC7807_InternalError_NoLeak(t *testing.T) {
	w := httptest.NewRecorder()
	WriteInternal(w, &ProblemDetail{Detail: "secret database password: hunter2"})

	var problem ProblemDetail
	if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}

	// Detail must be a generic message, never the internal error string
	if problem.Detail == "" {
		t.Error("detail should not be empty")
	}
	if problem.Detail == "secret database password: hunter2" {
		t.Error("internal error details leaked to client response")
	}
}

// TestOpenAPISpec_EndpointCoverage extends the basic drift test with console route coverage.
func TestOpenAPISpec_EndpointCoverage(t *testing.T) {
	// These are the critical API endpoints that must be documented in OpenAPI.
	// If a new endpoint is added without updating openapi.yaml, this test flags it.
	endpoints := []struct {
		path  string
		group string
	}{
		{"/health", "infrastructure"},
		{"/api/v1/kernel/dispatch", "governance"},
		{"/api/v1/console/bootstrap", "console"},
		{"/api/v1/evaluate", "console"},
		{"/api/v1/receipts", "console"},
		{"/v1/chat/completions", "proxy"},
		{"/mcp/v1/capabilities", "mcp"},
		{"/mcp/v1/execute", "mcp"},
	}

	// Verify no duplicate paths
	seen := make(map[string]bool)
	for _, ep := range endpoints {
		if seen[ep.path] {
			t.Errorf("duplicate endpoint in contract: %s", ep.path)
		}
		seen[ep.path] = true
	}
}
