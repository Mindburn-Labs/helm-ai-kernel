package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
)

func TestTenantScopedRuntimeAuthRequiresExplicitTenant(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	handler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("tenant-scoped handler should not run without an explicit tenant")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped route without tenant status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantScopedRuntimeAuthInjectsSelectedTenant(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
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
