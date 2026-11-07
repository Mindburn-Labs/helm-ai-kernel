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

// WriteBadRequest writes a 400 error response.
func WriteBadRequest(w http.ResponseWriter, detail string) {
	httperr.WriteBadRequest(w, detail)
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
