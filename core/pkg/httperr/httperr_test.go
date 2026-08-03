package httperr_test

import (
	"encoding/json"
	"errors"
	"go/build"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
)

func TestWriteError_RFC7807Envelope(t *testing.T) {
	w := httptest.NewRecorder()
	httperr.WriteError(w, http.StatusBadRequest, "Bad Request", "field is missing")

	if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}

	var problem httperr.ProblemDetail
	if err := json.NewDecoder(w.Body).Decode(&problem); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if problem.Status != http.StatusBadRequest {
		t.Errorf("problem.status = %d, want 400", problem.Status)
	}
	if problem.Title != "Bad Request" {
		t.Errorf("problem.title = %q, want %q", problem.Title, "Bad Request")
	}
	if problem.Detail != "field is missing" {
		t.Errorf("problem.detail = %q, want %q", problem.Detail, "field is missing")
	}
	if problem.Type != "https://helm.mindburn.run/errors/400" {
		t.Errorf("problem.type = %q", problem.Type)
	}
}

func TestWriteErrorR_EnrichesWithRequestContext(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("X-Request-ID", "req-123")
	httperr.WriteErrorR(w, httptest.NewRequest(http.MethodGet, "/api/v1/resource", nil),
		http.StatusNotFound, "Not Found", "resource does not exist")

	var problem httperr.ProblemDetail
	if err := json.NewDecoder(w.Body).Decode(&problem); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if problem.Instance != "/api/v1/resource" {
		t.Errorf("problem.instance = %q", problem.Instance)
	}
	if problem.TraceID != "req-123" {
		t.Errorf("problem.trace_id = %q", problem.TraceID)
	}
}

func TestStatusWriters(t *testing.T) {
	cases := []struct {
		name       string
		write      func(http.ResponseWriter)
		wantStatus int
		wantDetail string
	}{
		{"BadRequest", func(w http.ResponseWriter) { httperr.WriteBadRequest(w, "invalid input") }, 400, "invalid input"},
		{"Unauthorized", func(w http.ResponseWriter) { httperr.WriteUnauthorized(w, "token expired") }, 401, "token expired"},
		{"Unauthorized/default", func(w http.ResponseWriter) { httperr.WriteUnauthorized(w, "") }, 401, "Authentication required"},
		{"Forbidden", func(w http.ResponseWriter) { httperr.WriteForbidden(w, "") }, 403, "Insufficient permissions"},
		{"NotFound", func(w http.ResponseWriter) { httperr.WriteNotFound(w, "gone") }, 404, "gone"},
		{"MethodNotAllowed", httperr.WriteMethodNotAllowed, 405, "The HTTP method is not supported for this endpoint"},
		{"Conflict", func(w http.ResponseWriter) { httperr.WriteConflict(w, "duplicate key") }, 409, "duplicate key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.write(w)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			var problem httperr.ProblemDetail
			if err := json.NewDecoder(w.Body).Decode(&problem); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if problem.Detail != tc.wantDetail {
				t.Errorf("problem.detail = %q, want %q", problem.Detail, tc.wantDetail)
			}
			if problem.Status != tc.wantStatus {
				t.Errorf("problem.status = %d, want %d", problem.Status, tc.wantStatus)
			}
		})
	}
}

func TestWriteTooManyRequests_SetsRetryAfter(t *testing.T) {
	w := httptest.NewRecorder()
	httperr.WriteTooManyRequests(w, 30)

	if ra := w.Header().Get("Retry-After"); ra != "30" {
		t.Errorf("Retry-After = %q, want %q", ra, "30")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", w.Code)
	}
}

func TestWriteInternal_NeverLeaksTheError(t *testing.T) {
	w := httptest.NewRecorder()
	httperr.WriteInternal(w, errors.New("pq: connection refused to host=10.0.0.1"))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "10.0.0.1") {
		t.Errorf("internal error details leaked to client: %s", body)
	}
}

func TestProblemDetail_ImplementsError(t *testing.T) {
	var err error = &httperr.ProblemDetail{Title: "Unauthorized", Detail: "token expired"}
	if got := err.Error(); got != "Unauthorized: token expired" {
		t.Errorf("Error() = %q", got)
	}
}

// TestPackageIsStdlibOnly is the guard that makes this package worth existing.
// It exists so that pkg/auth — and anything else that only needs to write an
// error response — can do so without inheriting a dependency tree; the moment a
// non-stdlib import lands here that property is silently gone, and the
// otelhttp-through-pkg/api regression this package was created to fix (HELM-460)
// comes back through a different door.
func TestPackageIsStdlibOnly(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("ImportDir: %v", err)
	}
	for _, imp := range pkg.Imports {
		// Only stdlib paths lack a dot in their first segment.
		if strings.Contains(strings.SplitN(imp, "/", 2)[0], ".") {
			t.Errorf("non-stdlib import %q — httperr must stay a leaf package", imp)
		}
	}
}
