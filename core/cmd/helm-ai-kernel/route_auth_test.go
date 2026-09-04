package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"

	_ "modernc.org/sqlite"
)

// recordingPrincipalBindingStore is a fake store.PrincipalBindingStore that
// records every Exists call and panics if invoked with an empty tenant or
// principal ID — this pins down that requireRuntimeTenant must reject empty
// headers before ever reaching the store. existsErr/existsOK control the
// (bool, error) returned for non-empty lookups.
type recordingPrincipalBindingStore struct {
	calls     int
	existsOK  bool
	existsErr error
}

func (s *recordingPrincipalBindingStore) Upsert(ctx context.Context, b store.PrincipalBinding) error {
	return nil
}

func (s *recordingPrincipalBindingStore) Exists(ctx context.Context, tenantID, principalID string) (bool, error) {
	s.calls++
	if tenantID == "" || principalID == "" {
		panic("Exists called with an empty tenantID/principalID; the empty-header 403 must fire before any store lookup")
	}
	return s.existsOK, s.existsErr
}

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

func TestConfiguredTenantRuntimeAuthUsesSeparateControlCredential(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	handler := protectRuntimeHandler(RouteAuthConfiguredTenant, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer provider-secret" {
			t.Fatalf("provider Authorization = %q", got)
		}
		gotHash, ok := helmauth.AuthenticatedCredentialHash(r.Context())
		if !ok {
			t.Fatal("authenticated credential evidence is missing")
		}
		wantHash, _ := helmauth.AuthenticatedCredentialHash(helmauth.WithAuthenticatedCredential(context.Background(), testAdminAPIKey))
		if gotHash != wantHash {
			t.Fatalf("credential hash = %q, want %q", gotHash, wantHash)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set(runtimeAPIKeyHeader, testAdminAPIKey)
	req.Header.Set("Authorization", "Bearer provider-secret")
	req.Header.Set(tenantHeader, "tenant-a")
	req.Header.Set(principalHeader, "principal-a")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("tenant-scoped proxy auth status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConfiguredTenantRuntimeAuthExplicitControlCredentialDoesNotFallback(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	handler := protectRuntimeHandler(RouteAuthConfiguredTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run with an invalid explicit HELM control credential")
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set(runtimeAPIKeyHeader, "wrong-control-key")
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid explicit control credential status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConfiguredTenantRuntimeAuthUsesServerBindingWhenHeadersAreMissing(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	handler := protectRuntimeHandler(RouteAuthConfiguredTenant, func(w http.ResponseWriter, r *http.Request) {
		principal, err := helmauth.GetPrincipal(r.Context())
		if err != nil {
			t.Fatalf("configured principal missing: %v", err)
		}
		if principal.GetTenantID() != "tenant-a" || principal.GetID() != "principal-a" {
			t.Fatalf("configured identity = %s/%s", principal.GetTenantID(), principal.GetID())
		}
		if _, ok := helmauth.AuthenticatedCredentialHash(r.Context()); !ok {
			t.Fatal("authenticated credential evidence is missing")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set(runtimeAPIKeyHeader, testAdminAPIKey)
	req.Header.Set("Authorization", "Bearer provider-secret")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("configured tenant route status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConfiguredTenantRuntimeAuthRejectsCallerIdentityOverride(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")
	handler := protectRuntimeHandler(RouteAuthConfiguredTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("configured tenant handler should not run for a caller-selected identity")
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set(runtimeAPIKeyHeader, testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-b")
	req.Header.Set(principalHeader, "principal-b")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("configured tenant identity override status = %d body=%s", rec.Code, rec.Body.String())
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

func TestTenantScopedRuntimeAuthEmptyPrincipalHeaderSkipsStoreLookup(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")

	fake := &recordingPrincipalBindingStore{existsOK: true}
	SetPrincipalBindingStore(fake)
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })

	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("tenant-scoped handler should not run without explicit principal binding")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-a")
	// principalHeader intentionally left unset (empty).
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped route with empty principal header status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "requires explicit principal binding") {
		t.Fatalf("body = %s, want message containing %q", rec.Body.String(), "requires explicit principal binding")
	}
	if fake.calls != 0 {
		t.Fatalf("store.Exists called %d time(s), want 0 (empty-header 403 must precede any store lookup)", fake.calls)
	}
}

func TestTenantScopedRuntimeAuthStoreErrorFailsClosed(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-a")
	t.Setenv(runtimePrincipalIDEnv, "principal-a")

	fake := &recordingPrincipalBindingStore{existsOK: false, existsErr: errors.New("store unavailable")}
	SetPrincipalBindingStore(fake)
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })

	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("tenant-scoped handler should not run when the binding store errors")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-b")
	req.Header.Set(principalHeader, "principal-b")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped route with store error status = %d, want %d (fail closed) body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if fake.calls == 0 {
		t.Fatal("expected store.Exists to be called for the non-env pair")
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

func TestOrganizationRuntimeAuthBindsExplicitIdentity(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv("HELM_SERVICE_API_KEY", "service-secret")
	t.Setenv(organizationRuntimeAPIKeyEnv, testOrganizationRuntimeAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-1")
	t.Setenv(runtimePrincipalIDEnv, "runtime-1")
	handler := protectRuntimeHandler(RouteAuthOrganizationRuntime, func(w http.ResponseWriter, r *http.Request) {
		principal, err := helmauth.GetPrincipal(r.Context())
		if err != nil {
			t.Fatalf("principal missing from organization runtime context: %v", err)
		}
		if principal.GetID() != "runtime-1" || principal.GetTenantID() != "tenant-1" {
			t.Fatalf("principal = id:%q tenant:%q", principal.GetID(), principal.GetTenantID())
		}
		if roles := principal.GetRoles(); len(roles) != 1 || roles[0] != organizationRuntimeRole {
			t.Fatalf("roles = %#v", roles)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, companyActivationOrganizationRuntimePath, nil)
	req.Header.Set("Authorization", "Bearer "+testOrganizationRuntimeAPIKey)
	req.Header.Set(tenantHeader, "tenant-1")
	req.Header.Set(principalHeader, "runtime-1")
	req.Header.Set(workspaceHeader, "workspace-1")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("organization runtime auth status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOrganizationRuntimeAuthRejectsUnregisteredPrincipal(t *testing.T) {
	t.Setenv(organizationRuntimeAPIKeyEnv, testOrganizationRuntimeAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-1")
	t.Setenv(runtimePrincipalIDEnv, "runtime-1")
	SetPrincipalBindingStore(&recordingPrincipalBindingStore{})
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })
	handler := protectRuntimeHandler(RouteAuthOrganizationRuntime, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("organization-runtime handler should not run for an unregistered principal")
	})

	req := httptest.NewRequest(http.MethodPost, companyActivationOrganizationRuntimePath, nil)
	req.Header.Set("Authorization", "Bearer "+testOrganizationRuntimeAPIKey)
	req.Header.Set(tenantHeader, "tenant-1")
	req.Header.Set(principalHeader, "attacker")
	req.Header.Set(workspaceHeader, "workspace-1")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("unregistered organization-runtime principal status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOrganizationRuntimeAuthRequiresDistinctConfiguredCredential(t *testing.T) {
	for _, test := range []struct {
		name       string
		credential string
		admin      string
		service    string
	}{
		{name: "missing"},
		{name: "surrounding whitespace", credential: " padded "},
		{name: "control character", credential: "bad\nkey"},
		{name: "same as admin", credential: "shared", admin: "shared"},
		{name: "same as service", credential: "shared", service: "shared"},
		{name: "too long", credential: strings.Repeat("x", 4097)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(organizationRuntimeAPIKeyEnv, test.credential)
			t.Setenv("HELM_ADMIN_API_KEY", test.admin)
			t.Setenv("HELM_SERVICE_API_KEY", test.service)
			configured, err := configuredOrganizationRuntimeAPIKey()
			if test.name == "missing" {
				if err != nil || configured != "" {
					t.Fatalf("missing credential = %q, err=%v", configured, err)
				}
				return
			}
			if err == nil || configured != "" {
				t.Fatalf("invalid credential = %q, err=%v", configured, err)
			}
		})
	}
}
