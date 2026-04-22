package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
)

func TestWriteError_ContentType(t *testing.T) {
	w := httptest.NewRecorder()
	api.WriteError(w, http.StatusBadRequest, "Bad Request", "field is missing")

	if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("expected Content-Type 'application/problem+json', got %q", ct)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	var problem api.ProblemDetail
	if err := json.NewDecoder(w.Body).Decode(&problem); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if problem.Status != 400 {
		t.Errorf("expected problem.status=400, got %d", problem.Status)
	}
	if problem.Title != "Bad Request" {
		t.Errorf("expected title 'Bad Request', got %q", problem.Title)
	}
	if problem.Detail != "field is missing" {
		t.Errorf("expected detail 'field is missing', got %q", problem.Detail)
	}
}

func TestWriteInternal_SanitizesError(t *testing.T) {
	w := httptest.NewRecorder()
	api.WriteInternal(w, errors.New("pq: connection refused to host=10.0.0.1"))

	var problem api.ProblemDetail
	if err := json.NewDecoder(w.Body).Decode(&problem); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Must NOT contain internal error details
	if problem.Detail == "pq: connection refused to host=10.0.0.1" {
		t.Error("internal error details leaked to client")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
}

func TestWriteTooManyRequests_RetryAfterHeader(t *testing.T) {
	w := httptest.NewRecorder()
	api.WriteTooManyRequests(w, 30)

	if ra := w.Header().Get("Retry-After"); ra != "30" {
		t.Errorf("expected Retry-After '30', got %q", ra)
	}
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", w.Code)
	}
}

func TestWriteMethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	api.WriteMethodNotAllowed(w)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestWriteUnauthorized_DefaultDetail(t *testing.T) {
	w := httptest.NewRecorder()
	api.WriteUnauthorized(w, "")

	var problem api.ProblemDetail
	if err := json.NewDecoder(w.Body).Decode(&problem); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if problem.Detail != "Authentication required" {
		t.Errorf("expected default detail, got %q", problem.Detail)
	}
}

func TestWriteErrorR_EnrichesWithRequestContext(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/resource", nil)
	w := httptest.NewRecorder()
	w.Header().Set("X-Request-ID", "req-123")

	api.WriteErrorR(w, req, http.StatusBadRequest, "Bad Request", "bad input")

	var problem api.ProblemDetail
	if err := json.NewDecoder(w.Body).Decode(&problem); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if problem.Instance != "/api/v1/resource" {
		t.Fatalf("expected instance %q, got %q", "/api/v1/resource", problem.Instance)
	}
	if problem.TraceID != "req-123" {
		t.Fatalf("expected trace_id %q, got %q", "req-123", problem.TraceID)
	}
}
