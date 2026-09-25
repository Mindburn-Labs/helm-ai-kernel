// Package httperr — the one HELM API error model (target architecture §11.1).
//
// Every HTTP error body is an RFC 7807 problem whose extension members are a
// Connect error: code, message and details, with details holding exactly one
// helm.errors.v1.ErrorDetail (protocols/proto/helm/errors/v1/errors.proto)
// that carries the registered reason code and whether a retry can succeed.
// The HTTP status is the caller's; this package never changes it.
//
// The body also repeats the message under "error", the shape SDK releases up
// to v0.8.5 parse (audit 24-02). That member is deprecated and goes at the
// next major API version.
//
// This is a leaf package: it imports nothing beyond the standard library, so any
// layer may write an error response without inheriting a dependency tree. It
// exists because pkg/auth — a library concern — previously reached into the
// pkg/api HTTP *server* package for three response writers, and so dragged the
// whole server tree (including the OpenTelemetry SDK and OTLP exporters) into
// every binary that merely authenticated a request.
//
// pkg/api re-exports this surface for backwards compatibility; new code should
// depend on httperr directly.
package httperr

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// ErrorDetailType is the fully qualified protobuf name of the HELM detail.
const ErrorDetailType = "helm.errors.v1.ErrorDetail"

// ContentType is the media type of every HELM error body.
const ContentType = "application/problem+json"

// ProblemDetail is the HELM error body. All API error responses use it.
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

	// Code is the Connect error code for Status.
	Code string `json:"code"`
	// Message is the Connect error message; equal to Detail.
	Message string `json:"message"`
	// Details holds exactly one helm.errors.v1.ErrorDetail.
	Details []ErrorDetail `json:"details"`

	// Legacy is the deprecated "error" member for SDK releases up to v0.8.5.
	Legacy LegacyError `json:"error"`
}

// ErrorDetail is a Connect error detail holding a helm.errors.v1.ErrorDetail:
// Value is its protobuf binary, base64 without padding, and Debug the same
// fields as JSON.
type ErrorDetail struct {
	Type  string           `json:"type"`
	Value string           `json:"value"`
	Debug ErrorDetailField `json:"debug"`
}

// ErrorDetailField holds the helm.errors.v1.ErrorDetail fields.
type ErrorDetailField struct {
	// ReasonCode is a registered reason code as an open string, or empty.
	ReasonCode string `json:"reason_code"`
	// Retryable reports whether repeating the same request can succeed.
	Retryable bool `json:"retryable"`
}

// LegacyError is the error shape SDK releases up to v0.8.5 parse.
type LegacyError struct {
	Message    string `json:"message"`
	Type       string `json:"type"`
	Code       string `json:"code"`
	ReasonCode string `json:"reason_code"`
}

// Error implements the error interface.
func (p *ProblemDetail) Error() string {
	return fmt.Sprintf("%s: %s", p.Title, p.Detail)
}

// NewProblem builds the error body for status. reasonCode is a registered
// reason code, or empty when the error has none.
func NewProblem(status int, title, detail, reasonCode string) ProblemDetail {
	code := connectCode(status)
	field := ErrorDetailField{ReasonCode: reasonCode, Retryable: retryable(status)}
	return ProblemDetail{
		Type:    fmt.Sprintf("https://helm.mindburn.run/errors/%d", status),
		Title:   title,
		Status:  status,
		Detail:  detail,
		Code:    code,
		Message: detail,
		Details: []ErrorDetail{{Type: ErrorDetailType, Value: field.wire(), Debug: field}},
		Legacy:  LegacyError{Message: detail, Type: legacyType(status), Code: code, ReasonCode: reasonCode},
	}
}

// WriteProblem writes problem with its own status.
func WriteProblem(w http.ResponseWriter, problem ProblemDetail) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(problem.Status)
	_ = json.NewEncoder(w).Encode(problem)
}

// WriteError writes the HELM error body for status.
func WriteError(w http.ResponseWriter, status int, title, detail string) {
	WriteProblem(w, NewProblem(status, title, detail, ""))
}

// WriteErrorR is WriteError enriched with request context (trace_id from
// X-Request-ID, instance from the request path).
func WriteErrorR(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	problem := NewProblem(status, title, detail, "")
	problem.Instance = r.URL.Path
	problem.TraceID = w.Header().Get("X-Request-ID")
	WriteProblem(w, problem)
}

// wire encodes the fields as helm.errors.v1.ErrorDetail protobuf binary:
// field 1 (string) and field 2 (bool), each omitted at its zero value.
func (f ErrorDetailField) wire() string {
	var b []byte
	if f.ReasonCode != "" {
		b = append(b, 1<<3|2)
		b = binary.AppendUvarint(b, uint64(len(f.ReasonCode)))
		b = append(b, f.ReasonCode...)
	}
	if f.Retryable {
		b = append(b, 2<<3|0, 1)
	}
	return base64.RawStdEncoding.EncodeToString(b)
}

// connectCode maps an HTTP status to a Connect error code
// (https://connectrpc.com/docs/protocol/#error-codes).
func connectCode(status int) string {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusUnsupportedMediaType, http.StatusRequestEntityTooLarge:
		return "invalid_argument"
	case http.StatusUnauthorized:
		return "unauthenticated"
	case http.StatusForbidden:
		return "permission_denied"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "aborted"
	case http.StatusGone, http.StatusPreconditionFailed, http.StatusPreconditionRequired, http.StatusLocked:
		return "failed_precondition"
	case http.StatusTooManyRequests:
		return "resource_exhausted"
	case 499:
		return "canceled"
	case http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return "unimplemented"
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return "deadline_exceeded"
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return "unavailable"
	case http.StatusInternalServerError:
		return "internal"
	}
	if status >= 400 && status < 500 {
		return "invalid_argument"
	}
	return "unknown"
}

// retryable reports whether an error with this status can succeed on retry.
func retryable(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// legacyType maps a status onto the closed "type" values that SDK releases up
// to v0.8.5 accept.
func legacyType(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return "authentication_error"
	case status == http.StatusForbidden:
		return "permission_denied"
	case status == http.StatusNotFound:
		return "not_found"
	case status >= 500:
		return "internal_error"
	}
	return "invalid_request"
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
//
// On a request path prefer WriteInternalR: this variant has no context, so the
// record it emits carries no trace_id and cannot be joined to the span that
// produced it.
func WriteInternal(w http.ResponseWriter, err error) {
	// Log internally but never expose to client
	slog.Error("internal server error", "error", err)
	WriteError(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred. Please try again later.")
}

// WriteInternalR is WriteInternal for handlers that hold the request: the log
// record is emitted with r.Context(), so the root slog handler
// (tracing.NewSlogHandler) stamps it with trace_id/span_id/correlation_id and
// the 500 can be joined to its server span. The err parameter is logged but
// NEVER exposed to the client.
//
// The response is byte-identical to WriteInternal's — only the log record
// changes — so swapping a call site cannot alter an API contract.
func WriteInternalR(w http.ResponseWriter, r *http.Request, err error) {
	// Log internally but never expose to client
	slog.ErrorContext(r.Context(), "internal server error", "error", err)
	WriteError(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred. Please try again later.")
}
