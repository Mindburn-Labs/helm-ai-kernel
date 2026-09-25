package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// HELM-780: GET /api/v1/budget/status answered a constant "enforcer: postgres,
// status: active" although no shipped binary wires a budget tracker (CTL-011).
// The route is gone, so no caller can read an enforcement claim nothing makes.
func TestBudgetStatusRouteIsNotRouted(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterSubsystemRoutes(mux, svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/budget/status", nil)
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (not routed); body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, `"active"`) || strings.Contains(body, `"enforcer"`) {
		t.Fatalf("retired budget status route still reports an enforcer: %s", body)
	}
	for _, spec := range RuntimeRouteSpecs() {
		if spec.Path == "/api/v1/budget/status" {
			t.Fatalf("route registry still declares %s %s", spec.Method, spec.Path)
		}
	}
}

// HELM-780: POST /api/v1/kernel/approve could never succeed, because nothing
// registered a pending approval. It stays behind the service credential and
// answers 501 until the deprecated operation leaves the contract.
func TestKernelApproveIsRetiredBehindServiceAuth(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	t.Setenv("HELM_SERVICE_API_KEY", "service-secret")
	mux := http.NewServeMux()
	RegisterSubsystemRoutes(mux, svc)

	body := `{"intent_hash":"sha256:intent","public_key":"` + strings.Repeat("ab", 32) + `","signature":"` + strings.Repeat("cd", 64) + `"}`
	cases := []struct {
		name   string
		method string
		token  string
		want   int
	}{
		{"no credential", http.MethodPost, "", http.StatusUnauthorized},
		{"admin credential is not the service credential", http.MethodPost, testAdminAPIKey, http.StatusUnauthorized},
		{"service credential, wrong method", http.MethodGet, "service-secret", http.StatusMethodNotAllowed},
		{"service credential", http.MethodPost, "service-secret", http.StatusNotImplemented},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v1/kernel/approve", strings.NewReader(body))
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "APPROVED") {
				t.Fatalf("retired approve route claims an approval: %s", rec.Body.String())
			}
		})
	}
}
