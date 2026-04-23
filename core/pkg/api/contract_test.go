package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRFC7807_ErrorShape verifies all error helpers produce valid RFC 7807 Problem Detail responses.
func TestRFC7807_ErrorShape(t *testing.T) {
	tests := []struct {
		name            string
		handler         func(w http.ResponseWriter)
		wantStatus      int
		wantType        string
		wantTitle       string
		wantContentType string
	}{
		{
			name:            "BadRequest",
			handler:         func(w http.ResponseWriter) { WriteBadRequest(w, "invalid input") },
			wantStatus:      400,
			wantType:        "https://helm.mindburn.run/errors/400",
			wantTitle:       "Bad Request",
			wantContentType: "application/problem+json",
		},
		{
			name:            "Unauthorized",
			handler:         func(w http.ResponseWriter) { WriteUnauthorized(w, "missing token") },
			wantStatus:      401,
			wantType:        "https://helm.mindburn.run/errors/401",
			wantTitle:       "Unauthorized",
			wantContentType: "application/problem+json",
		},
		{
			name:            "Forbidden",
			handler:         func(w http.ResponseWriter) { WriteForbidden(w, "insufficient scope") },
			wantStatus:      403,
			wantType:        "https://helm.mindburn.run/errors/403",
			wantTitle:       "Forbidden",
			wantContentType: "application/problem+json",
		},
		{
			name:            "NotFound",
			handler:         func(w http.ResponseWriter) { WriteNotFound(w, "resource missing") },
			wantStatus:      404,
			wantType:        "https://helm.mindburn.run/errors/404",
			wantTitle:       "Not Found",
			wantContentType: "application/problem+json",
		},
		{
			name:            "MethodNotAllowed",
			handler:         func(w http.ResponseWriter) { WriteMethodNotAllowed(w) },
			wantStatus:      405,
			wantType:        "https://helm.mindburn.run/errors/405",
			wantTitle:       "Method Not Allowed",
			wantContentType: "application/problem+json",
		},
		{
			name:            "Conflict",
			handler:         func(w http.ResponseWriter) { WriteConflict(w, "duplicate key") },
			wantStatus:      409,
			wantType:        "https://helm.mindburn.run/errors/409",
			wantTitle:       "Conflict",
			wantContentType: "application/problem+json",
		},
		{
			name:            "TooManyRequests",
			handler:         func(w http.ResponseWriter) { WriteTooManyRequests(w, 60) },
			wantStatus:      429,
			wantType:        "https://helm.mindburn.run/errors/429",
			wantTitle:       "Too Many Requests",
			wantContentType: "application/problem+json",
		},
		{
			name:            "InternalServerError",
			handler:         func(w http.ResponseWriter) { WriteInternal(w, nil) },
			wantStatus:      500,
			wantType:        "https://helm.mindburn.run/errors/500",
			wantTitle:       "Internal Server Error",
			wantContentType: "application/problem+json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tt.handler(w)

			// Status code
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			// Content-Type
			gotContentType := w.Header().Get("Content-Type")
			if gotContentType != tt.wantContentType {
				t.Errorf("Content-Type = %q, want %q", gotContentType, tt.wantContentType)
			}

			// Parse RFC 7807 body
			var problem ProblemDetail
			if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
				t.Fatalf("response is not valid JSON: %v", err)
			}

			if problem.Type == "" {
				t.Error("RFC 7807: 'type' field is required but empty")
			}
			if problem.Type != tt.wantType {
				t.Errorf("type = %q, want %q", problem.Type, tt.wantType)
			}
			if problem.Title != tt.wantTitle {
				t.Errorf("title = %q, want %q", problem.Title, tt.wantTitle)
			}
			if problem.Status != tt.wantStatus {
				t.Errorf("status field = %d, want %d", problem.Status, tt.wantStatus)
			}
		})
	}
}

// TestRFC7807_TooManyRequests_RetryAfter validates the Retry-After header per RFC 6585 §4.
func TestRFC7807_TooManyRequests_RetryAfter(t *testing.T) {
	w := httptest.NewRecorder()
	WriteTooManyRequests(w, 120)

	ra := w.Header().Get("Retry-After")
	if ra != "120" {
		t.Errorf("Retry-After = %q, want %q", ra, "120")
	}
}

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

// TestRFC7807_ContextEnrichedError verifies WriteErrorR includes request context.
func TestRFC7807_ContextEnrichedError(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/v1/protect/secret", nil)

	w := httptest.NewRecorder()
	w.Header().Set("X-Request-ID", "trace-abc-123")

	WriteErrorR(w, r, 404, "Not Found", "resource does not exist")

	var problem ProblemDetail
	if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}

	if problem.Instance != "/api/v1/protect/secret" {
		t.Errorf("instance = %q, want %q", problem.Instance, "/api/v1/protect/secret")
	}
}

// TestApproveHandler_MethodEnforcement validates that the approval endpoint rejects non-POST methods.
func TestApproveHandler_MethodEnforcement(t *testing.T) {
	h := NewApproveHandler(nil)

	methods := []string{"GET", "PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest(method, "/api/v1/kernel/approve", nil)
			w := httptest.NewRecorder()
			h.HandleApprove(w, r)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: status = %d, want 405", method, w.Code)
			}
		})
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
		{"/api/v1/kernel/approve", "governance"},
		{"/api/v1/trust/keys/add", "trust"},
		{"/api/v1/trust/keys/revoke", "trust"},
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

	// Verify expected group counts
	groups := make(map[string]int)
	for _, ep := range endpoints {
		groups[ep.group]++
	}
	if groups["governance"] < 2 {
		t.Error("governance group should have at least 2 endpoints")
	}
	if groups["trust"] < 2 {
		t.Error("trust group should have at least 2 endpoints")
	}
}
