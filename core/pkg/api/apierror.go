// Package api — RFC 7807 Problem Detail error responses for the HELM API.
//
// The implementation moved to the stdlib-only leaf package pkg/httperr so that
// libraries such as pkg/auth can write error responses without importing this
// HTTP server package. Everything below forwards there; the names stay because
// pkg/api is public OSS API and removing them would be a breaking change.
package api

import (
	"net/http"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
)

// ProblemDetail implements RFC 7807 (Problem Details for HTTP APIs).
// All API error responses must use this format.
//
// An alias, not a defined type: callers hand *ProblemDetail across the httperr
// boundary (WriteInternal takes one as an error), and a distinct type would
// silently break them.
type ProblemDetail = httperr.ProblemDetail

// WriteError writes an RFC 7807 Problem Detail JSON response.
func WriteError(w http.ResponseWriter, status int, title, detail string) {
	httperr.WriteError(w, status, title, detail)
}

// WriteErrorR writes an RFC 7807 response enriched with request context
// (trace_id from X-Request-ID, instance from request URI).
func WriteErrorR(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	httperr.WriteErrorR(w, r, status, title, detail)
}

// WriteBadRequest writes a 400 error response.
func WriteBadRequest(w http.ResponseWriter, detail string) {
	httperr.WriteBadRequest(w, detail)
}

// WriteUnauthorized writes a 401 error response.
//
// Deprecated: use httperr.WriteUnauthorized. Authentication middleware is a
// library concern and must not import this server package.
func WriteUnauthorized(w http.ResponseWriter, detail string) {
	httperr.WriteUnauthorized(w, detail)
}

// WriteForbidden writes a 403 error response.
func WriteForbidden(w http.ResponseWriter, detail string) {
	httperr.WriteForbidden(w, detail)
}

// WriteNotFound writes a 404 error response.
func WriteNotFound(w http.ResponseWriter, detail string) {
	httperr.WriteNotFound(w, detail)
}

// WriteMethodNotAllowed writes a 405 error response.
func WriteMethodNotAllowed(w http.ResponseWriter) {
	httperr.WriteMethodNotAllowed(w)
}

// WriteConflict writes a 409 error response (used for idempotency).
func WriteConflict(w http.ResponseWriter, detail string) {
	httperr.WriteConflict(w, detail)
}

// WriteTooManyRequests writes a 429 error response with Retry-After header.
//
// Deprecated: use httperr.WriteTooManyRequests. Rate-limit middleware is a
// library concern and must not import this server package.
func WriteTooManyRequests(w http.ResponseWriter, retryAfterSecs int) {
	httperr.WriteTooManyRequests(w, retryAfterSecs)
}

// WriteInternal writes a 500 error response.
// The err parameter is logged but NEVER exposed to the client.
//
// On a request path prefer WriteInternalR — see httperr.WriteInternalR.
func WriteInternal(w http.ResponseWriter, err error) {
	httperr.WriteInternal(w, err)
}

// WriteInternalR writes a 500 error response and logs the cause with the
// request context attached, so the record carries trace_id/span_id. The
// response is identical to WriteInternal's.
func WriteInternalR(w http.ResponseWriter, r *http.Request, err error) {
	httperr.WriteInternalR(w, r, err)
}
