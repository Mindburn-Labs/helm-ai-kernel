package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"

	_ "modernc.org/sqlite"
)

// newRouteAuthTestBindingStore returns a fresh in-memory SQLite-backed
// store.PrincipalBindingStore for tenant-gate registry tests.
func newRouteAuthTestBindingStore(t *testing.T) (store.PrincipalBindingStore, func()) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.NewSQLitePrincipalBindingStore(db)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return s, func() { _ = db.Close() }
}

func TestTenantScopedRuntimeAuthRejectsMissingTenantBinding(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "")
	t.Setenv(runtimePrincipalIDEnv, "")
	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("tenant-scoped handler should not run without explicit tenant binding")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(principalHeader, "system-admin")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped route without tenant status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantScopedRuntimeAuthBindsConfiguredTenantAndPrincipal(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		principal, err := helmauth.GetPrincipal(r.Context())
		if err != nil {
			t.Fatalf("principal missing from tenant-scoped context: %v", err)
		}
		if principal.GetTenantID() != "tenant-a" {
			t.Fatalf("tenant = %q, want tenant-a", principal.GetTenantID())
		}
		if principal.GetID() != "principal-a" {
			t.Fatalf("principal = %q, want principal-a", principal.GetID())
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-a")
	req.Header.Set(principalHeader, "principal-a")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("tenant-scoped route with tenant status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantScopedRuntimeAuthRejectsExpiredQuickstartSession(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", "quickstart-session")
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	t.Setenv(quickstartExpiresAtEnv, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano))
	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("tenant-scoped handler should not run after quickstart session expiry")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evaluate", nil)
	req.Header.Set("Authorization", "Bearer quickstart-session")
	req.Header.Set(tenantHeader, "tenant-a")
	req.Header.Set(principalHeader, "principal-a")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("tenant-scoped route with expired quickstart session status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminRuntimeAuthRejectsExpiredQuickstartSession(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", "quickstart-session")
	t.Setenv(quickstartExpiresAtEnv, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano))
	handler := protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("admin handler should not run after quickstart session expiry")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/console/diagnostics", nil)
	req.Header.Set("Authorization", "Bearer quickstart-session")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin route with expired quickstart session status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantScopedRuntimeAuthAllowsUnexpiredQuickstartSession(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", "quickstart-session")
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	t.Setenv(quickstartExpiresAtEnv, time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano))
	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evaluate", nil)
	req.Header.Set("Authorization", "Bearer quickstart-session")
	req.Header.Set(tenantHeader, "tenant-a")
	req.Header.Set(principalHeader, "principal-a")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("tenant-scoped route with unexpired quickstart session status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantScopedRuntimeAuthRejectsTenantMismatch(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("tenant-scoped handler should not run on tenant mismatch")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-b")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped route with tenant mismatch status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantScopedRuntimeAuthRejectsMissingPrincipalBinding(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("tenant-scoped handler should not run without explicit principal binding")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-a")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped route without principal status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantScopedRuntimeAuthRejectsPrincipalMismatch(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("tenant-scoped handler should not run on principal mismatch")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-a")
	req.Header.Set(principalHeader, "principal-b")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped route with principal mismatch status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServiceInternalRuntimeAuthFailsClosedWhenUnconfigured(t *testing.T) {
	t.Setenv("HELM_SERVICE_API_KEY", "")
	handler := protectRuntimeHandler(RouteAuthService, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("service-internal handler should not run when service key is unconfigured")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kernel/approve", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("service-internal route without configured token status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantScopedRuntimeAuthAllowsRegisteredNonEnvBinding(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")

	bindingStore, cleanup := newRouteAuthTestBindingStore(t)
	defer cleanup()
	if err := bindingStore.Upsert(context.Background(), store.PrincipalBinding{
		TenantID:    "tenant-b",
		PrincipalID: "principal-b",
	}); err != nil {
		t.Fatalf("seeding binding store: %v", err)
	}
	SetPrincipalBindingStore(bindingStore)
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })

	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		principal, err := helmauth.GetPrincipal(r.Context())
		if err != nil {
			t.Fatalf("principal missing from tenant-scoped context: %v", err)
		}
		if principal.GetTenantID() != "tenant-b" {
			t.Fatalf("tenant = %q, want tenant-b", principal.GetTenantID())
		}
		if principal.GetID() != "principal-b" {
			t.Fatalf("principal = %q, want principal-b", principal.GetID())
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-b")
	req.Header.Set(principalHeader, "principal-b")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("tenant-scoped route with registered non-env binding status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantScopedRuntimeAuthRejectsNonEnvPairNotInStore(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")

	bindingStore, cleanup := newRouteAuthTestBindingStore(t)
	defer cleanup()
	SetPrincipalBindingStore(bindingStore)
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })

	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("tenant-scoped handler should not run for an unregistered non-env pair")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-c")
	req.Header.Set(principalHeader, "principal-c")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped route with unregistered non-env pair status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantScopedRuntimeAuthNilStoreAllowsEnvPair(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")

	SetPrincipalBindingStore(nil)
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })

	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-a")
	req.Header.Set(principalHeader, "principal-a")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("tenant-scoped route with nil store and env pair status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantScopedRuntimeAuthNilStoreRejectsNonEnvPair(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")

	SetPrincipalBindingStore(nil)
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })

	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("tenant-scoped handler should not run for a non-env pair when store is nil")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-b")
	req.Header.Set(principalHeader, "principal-b")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped route with nil store and non-env pair status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServiceInternalRuntimeAuthRequiresConfiguredToken(t *testing.T) {
	t.Setenv("HELM_SERVICE_API_KEY", "service-secret")
	handler := protectRuntimeHandler(RouteAuthService, func(w http.ResponseWriter, r *http.Request) {
		principal, err := helmauth.GetPrincipal(r.Context())
		if err != nil {
			t.Fatalf("principal missing from service context: %v", err)
		}
		if principal.GetID() != servicePrincipalID {
			t.Fatalf("service principal = %q, want %q", principal.GetID(), servicePrincipalID)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kernel/approve", nil)
	req.Header.Set("Authorization", "Bearer service-secret")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("service-internal route with configured token status = %d body=%s", rec.Code, rec.Body.String())
	}
}
