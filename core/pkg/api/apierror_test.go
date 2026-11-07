package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
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

func TestWriteMethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	api.WriteMethodNotAllowed(w)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}
