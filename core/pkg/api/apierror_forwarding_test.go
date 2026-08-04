package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
)

// The pkg/api error writers became forwarders to pkg/httperr so that pkg/auth
// could stop importing this server package (HELM-460). pkg/api is public OSS
// API, so the claim "no behavior changed" has to be asserted rather than
// assumed: every wrapper must still produce the byte-identical status, headers
// and body its httperr counterpart does.
func TestAPIWrappers_ForwardIdenticallyToHTTPErr(t *testing.T) {
	cases := []struct {
		name    string
		viaAPI  func(http.ResponseWriter)
		viaHTTP func(http.ResponseWriter)
	}{
		{
			name:    "WriteError",
			viaAPI:  func(w http.ResponseWriter) { api.WriteError(w, http.StatusTeapot, "Teapot", "short and stout") },
			viaHTTP: func(w http.ResponseWriter) { httperr.WriteError(w, http.StatusTeapot, "Teapot", "short and stout") },
		},
		{
			name:    "WriteBadRequest",
			viaAPI:  func(w http.ResponseWriter) { api.WriteBadRequest(w, "field is missing") },
			viaHTTP: func(w http.ResponseWriter) { httperr.WriteBadRequest(w, "field is missing") },
		},
		{
			name:    "WriteUnauthorized",
			viaAPI:  func(w http.ResponseWriter) { api.WriteUnauthorized(w, "token expired") },
			viaHTTP: func(w http.ResponseWriter) { httperr.WriteUnauthorized(w, "token expired") },
		},
		{
			// The empty detail exercises the default-substitution branch, which
			// is the one pkg/auth relies on for its fail-closed responses.
			name:    "WriteUnauthorized/empty detail",
			viaAPI:  func(w http.ResponseWriter) { api.WriteUnauthorized(w, "") },
			viaHTTP: func(w http.ResponseWriter) { httperr.WriteUnauthorized(w, "") },
		},
		{
			name:    "WriteForbidden",
			viaAPI:  func(w http.ResponseWriter) { api.WriteForbidden(w, "") },
			viaHTTP: func(w http.ResponseWriter) { httperr.WriteForbidden(w, "") },
		},
		{
			name:    "WriteNotFound",
			viaAPI:  func(w http.ResponseWriter) { api.WriteNotFound(w, "resource missing") },
			viaHTTP: func(w http.ResponseWriter) { httperr.WriteNotFound(w, "resource missing") },
		},
		{
			name:    "WriteMethodNotAllowed",
			viaAPI:  api.WriteMethodNotAllowed,
			viaHTTP: httperr.WriteMethodNotAllowed,
		},
		{
			name:    "WriteConflict",
			viaAPI:  func(w http.ResponseWriter) { api.WriteConflict(w, "duplicate key") },
			viaHTTP: func(w http.ResponseWriter) { httperr.WriteConflict(w, "duplicate key") },
		},
		{
			// Retry-After is set on the header, not the body — a forwarder that
			// dropped it would still pass a body-only comparison.
			name:    "WriteTooManyRequests",
			viaAPI:  func(w http.ResponseWriter) { api.WriteTooManyRequests(w, 30) },
			viaHTTP: func(w http.ResponseWriter) { httperr.WriteTooManyRequests(w, 30) },
		},
		{
			name:    "WriteInternal",
			viaAPI:  func(w http.ResponseWriter) { api.WriteInternal(w, errSentinel) },
			viaHTTP: func(w http.ResponseWriter) { httperr.WriteInternal(w, errSentinel) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := httptest.NewRecorder()
			tc.viaAPI(got)

			want := httptest.NewRecorder()
			tc.viaHTTP(want)

			if got.Code != want.Code {
				t.Errorf("status: api=%d httperr=%d", got.Code, want.Code)
			}
			if got.Body.String() != want.Body.String() {
				t.Errorf("body:\n api=%q\n httperr=%q", got.Body.String(), want.Body.String())
			}
			for k, wantVals := range want.Header() {
				gotVals := got.Header()[k]
				if len(gotVals) != len(wantVals) {
					t.Errorf("header %q: api=%v httperr=%v", k, gotVals, wantVals)
					continue
				}
				for i := range wantVals {
					if gotVals[i] != wantVals[i] {
						t.Errorf("header %q: api=%v httperr=%v", k, gotVals, wantVals)
						break
					}
				}
			}
			if len(got.Header()) != len(want.Header()) {
				t.Errorf("header count: api=%v httperr=%v", got.Header(), want.Header())
			}
		})
	}
}

// TestWriteErrorR_ForwardsIdentically covers the request-enriched writer, which
// takes an extra *http.Request and so cannot share the table above.
func TestWriteErrorR_ForwardsIdentically(t *testing.T) {
	newReq := func() *http.Request { return httptest.NewRequest(http.MethodGet, "/api/v1/resource", nil) }

	got := httptest.NewRecorder()
	got.Header().Set("X-Request-ID", "req-123")
	api.WriteErrorR(got, newReq(), http.StatusBadRequest, "Bad Request", "bad input")

	want := httptest.NewRecorder()
	want.Header().Set("X-Request-ID", "req-123")
	httperr.WriteErrorR(want, newReq(), http.StatusBadRequest, "Bad Request", "bad input")

	if got.Code != want.Code {
		t.Errorf("status: api=%d httperr=%d", got.Code, want.Code)
	}
	if got.Body.String() != want.Body.String() {
		t.Errorf("body:\n api=%q\n httperr=%q", got.Body.String(), want.Body.String())
	}
}

// TestProblemDetailIsHTTPErrAlias fails to compile — not merely fails — if
// api.ProblemDetail is ever redefined as a distinct type, which would break
// every caller that passes one across the boundary.
func TestProblemDetailIsHTTPErrAlias(t *testing.T) {
	var p api.ProblemDetail
	var q *httperr.ProblemDetail = &p
	q.Title = "Teapot"
	if p.Title != "Teapot" {
		t.Fatalf("api.ProblemDetail is not an alias of httperr.ProblemDetail")
	}
}

// errSentinel keeps WriteInternal's two calls comparable: the error is logged,
// never rendered, so any non-nil value works as long as both sides get the same.
var errSentinel = &httperr.ProblemDetail{Title: "internal", Detail: "secret database password"}
