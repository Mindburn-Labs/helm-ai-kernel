// Package api — RFC 7807 Problem Detail error responses for the HELM API.
package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// ProblemDetail implements RFC 7807 (Problem Details for HTTP APIs).
// All API error responses must use this format.
type ProblemDetail struct {
	// Type is a URI reference that identifies the problem type.
	Type string `json:"type"`
	// Title is a short, human-readable summary of the problem type.
	Title string `json:"title"`
	// Status is the HTTP status code.
	Status int `json:"status"`
	// Detail is a human-readable explanation specific to this occurrence.
	Detail string `json:"detail,omitempty"`
	// Instance is a URI reference identifying the specific occurrence.
	Instance string `json:"instance,omitempty"`
	// TraceID links to the distributed trace for this request.
	TraceID string `json:"trace_id,omitempty"`
}

// Error implements the error interface.
func (p *ProblemDetail) Error() string {
	return fmt.Sprintf("%s: %s", p.Title, p.Detail)
}

// WriteError writes an RFC 7807 Problem Detail JSON response.
func WriteError(w http.ResponseWriter, status int, title, detail string) {
	problem := &ProblemDetail{
		Type:   fmt.Sprintf("https://helm.mindburn.run/errors/%d", status),
		Title:  title,
		Status: status,
		Detail: detail,
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem)
}

// WriteErrorR writes an RFC 7807 response enriched with request context
// (trace_id from X-Request-ID, instance from request URI).
func WriteErrorR(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	problem := &ProblemDetail{
		Type:     fmt.Sprintf("https://helm.mindburn.run/errors/%d", status),
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path,
		TraceID:  w.Header().Get("X-Request-ID"),
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem)
}

// WriteBadRequest writes a 400 error response.
func WriteBadRequest(w http.ResponseWriter, detail string) {
	WriteError(w, http.StatusBadRequest, "Bad Request", detail)
}

// WriteUnauthorized writes a 401 error response.
func WriteUnauthorized(w http.ResponseWriter, detail string) {
	if detail == "" {
		detail = "Authentication required"
	}
	WriteError(w, http.StatusUnauthorized, "Unauthorized", detail)
}

// WriteForbidden writes a 403 error response.
func WriteForbidden(w http.ResponseWriter, detail string) {
	if detail == "" {
		detail = "Insufficient permissions"
	}
	WriteError(w, http.StatusForbidden, "Forbidden", detail)
}

// WriteNotFound writes a 404 error response.
func WriteNotFound(w http.ResponseWriter, detail string) {
	WriteError(w, http.StatusNotFound, "Not Found", detail)
}

// WriteMethodNotAllowed writes a 405 error response.
func WriteMethodNotAllowed(w http.ResponseWriter) {
	WriteError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "The HTTP method is not supported for this endpoint")
}

// WriteConflict writes a 409 error response (used for idempotency).
func WriteConflict(w http.ResponseWriter, detail string) {
	WriteError(w, http.StatusConflict, "Conflict", detail)
}

// WriteTooManyRequests writes a 429 error response with Retry-After header.
func WriteTooManyRequests(w http.ResponseWriter, retryAfterSecs int) {
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfterSecs))
	WriteError(w, http.StatusTooManyRequests, "Too Many Requests", "Rate limit exceeded. Retry after the specified interval.")
}

// WriteInternal writes a 500 error response.
// The err parameter is logged but NEVER exposed to the client.
func WriteInternal(w http.ResponseWriter, err error) {
	// Log internally but never expose to client
	slog.Error("internal server error", "error", err)
	WriteError(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred. Please try again later.")
}
