package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("principal binding register status = %d body=%s", rec.Code, rec.Body.String())
	}

	ok, err := bindingStore.Exists(context.Background(), "acme", "acme-admin")
	if err != nil {
		t.Fatalf("Exists returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected binding to exist after registration")
	}

	// Re-POST the same pair must remain idempotent (still 2xx).
	rec2 := postPrincipalBindingForTest(mux, testAdminAPIKey, "acme", "acme-admin")
	if rec2.Code < 200 || rec2.Code >= 300 {
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
