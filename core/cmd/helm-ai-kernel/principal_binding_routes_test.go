package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"

	_ "modernc.org/sqlite"
)

func newPrincipalBindingTestServices(t *testing.T) (*Services, store.PrincipalBindingStore, func()) {
	t.Helper()
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	bindingStore, err := store.NewSQLitePrincipalBindingStore(db)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return &Services{PrincipalBindings: bindingStore}, bindingStore, func() { _ = db.Close() }
}

func postPrincipalBindingForTest(mux *http.ServeMux, bearer, tenantID, principalID string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"tenant_id": tenantID, "principal_id": principalID})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/principal-bindings", bytes.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestPrincipalBindingRoutesUpsertsAndIsIdempotent(t *testing.T) {
	svc, bindingStore, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})

	rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "acme", "acme-admin")
	if rec.Code != http.StatusCreated {
		t.Fatalf("principal binding register status = %d body=%s", rec.Code, rec.Body.String())
	}

	ok, err := bindingStore.Exists(context.Background(), "acme", "acme-admin")
	if err != nil {
		t.Fatalf("Exists returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected binding to exist after registration")
	}

	// Re-POST the same pair must remain idempotent: 200, nothing new.
	rec2 := postPrincipalBindingForTest(mux, testAdminAPIKey, "acme", "acme-admin")
	if rec2.Code != http.StatusOK {
		t.Fatalf("repeat principal binding register status = %d body=%s", rec2.Code, rec2.Body.String())
	}
}

func TestPrincipalBindingRoutesRejectMissingBearer(t *testing.T) {
	svc, _, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})

	rec := postPrincipalBindingForTest(mux, "", "acme", "acme-admin")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("principal binding register without bearer status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPrincipalBindingRoutesRejectInvalidBearer(t *testing.T) {
	svc, _, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})

	rec := postPrincipalBindingForTest(mux, "not-the-admin-key", "acme", "acme-admin")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("principal binding register with invalid bearer status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPrincipalBindingRoutesRejectMissingFields(t *testing.T) {
	svc, _, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})

	rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "", "x")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("principal binding register with missing tenant_id status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec2 := postPrincipalBindingForTest(mux, testAdminAPIKey, "acme", "")
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("principal binding register with missing principal_id status = %d body=%s", rec2.Code, rec2.Body.String())
	}
}

// ADR-0005 §11: binding a principal that is already bound in another tenant is
// refused with 409 TENANT_ISOLATION and counted; nothing is written, and the
// original binding stays idempotent.
func TestPrincipalBindingRouteRefusesCrossTenantRebind(t *testing.T) {
	t.Setenv(crossTenantPrincipalsEnv, "")
	svc, bindingStore, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})
	refused := func() float64 { return testutil.ToFloat64(controlPlaneIdentityMetrics.rebindRefused) }

	if rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "tenant-a", "member-a"); rec.Code != http.StatusCreated {
		t.Fatalf("first bind: %d %s", rec.Code, rec.Body.String())
	}
	before := refused()
	rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "tenant-b", "member-a")
	if rec.Code != http.StatusConflict {
		t.Fatalf("bind into a second tenant: %d %s, want 409", rec.Code, rec.Body.String())
	}
	var problem httperr.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if len(problem.Details) != 1 || problem.Details[0].Debug.ReasonCode != "TENANT_ISOLATION" {
		t.Fatalf("409 reason code = %+v, want TENANT_ISOLATION", problem.Details)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("tenant-a")) {
		t.Fatalf("the refusal names the other tenant: %s", rec.Body.String())
	}
	if refused() != before+1 {
		t.Fatalf("helm_principal_rebind_refused_total = %v, want %v", refused(), before+1)
	}
	if ok, err := bindingStore.Exists(context.Background(), "tenant-b", "member-a"); err != nil || ok {
		t.Fatalf("a refused bind was written: ok=%v err=%v", ok, err)
	}
	if rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "tenant-a", "member-a"); rec.Code != http.StatusOK {
		t.Fatalf("re-bind in the principal's own tenant: %d, want 200", rec.Code)
	}
}

// Only principals listed in HELM_CROSS_TENANT_PRINCIPALS may hold bindings in
// several tenants.
func TestPrincipalBindingRouteAllowsListedCrossTenantPrincipals(t *testing.T) {
	t.Setenv(crossTenantPrincipalsEnv, " helm-workflow-runner , ,other-runner")
	svc, bindingStore, cleanup := newPrincipalBindingTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterPrincipalBindingRoutes(mux, svc, serverOptions{Mode: "serve"})
	before := testutil.ToFloat64(controlPlaneIdentityMetrics.rebindRefused)

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if rec := postPrincipalBindingForTest(mux, testAdminAPIKey, tenant, "helm-workflow-runner"); rec.Code != http.StatusCreated {
			t.Fatalf("listed principal into %s: %d %s", tenant, rec.Code, rec.Body.String())
		}
		if ok, err := bindingStore.Exists(context.Background(), tenant, "helm-workflow-runner"); err != nil || !ok {
			t.Fatalf("listed principal not bound in %s: ok=%v err=%v", tenant, ok, err)
		}
	}
	if got := testutil.ToFloat64(controlPlaneIdentityMetrics.rebindRefused); got != before {
		t.Fatalf("a listed principal's bind was counted as refused: %v -> %v", before, got)
	}
	postPrincipalBindingForTest(mux, testAdminAPIKey, "tenant-a", "member-a")
	if rec := postPrincipalBindingForTest(mux, testAdminAPIKey, "tenant-b", "member-a"); rec.Code != http.StatusConflict {
		t.Fatalf("an unlisted principal into a second tenant: %d, want 409", rec.Code)
	}
}
