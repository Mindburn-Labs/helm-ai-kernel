package main

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
)

const (
	tenantHeader           = "X-Helm-Tenant-ID"
	principalHeader        = "X-Helm-Principal-ID"
	runtimeTenantIDEnv     = "HELM_RUNTIME_TENANT_ID"
	runtimePrincipalIDEnv  = "HELM_RUNTIME_PRINCIPAL_ID"
	defaultRuntimeTenantID = "default"
	serviceAPIKeyEnv       = "HELM_SERVICE_API_KEY"
	servicePrincipalID     = "service-internal"
)

func protectRuntimeHandler(auth RouteAuth, handler http.HandlerFunc) http.HandlerFunc {
	switch auth {
	case RouteAuthPublic:
		return handler
	case RouteAuthAdmin, RouteAuthAuthenticated:
		return requireRuntimeAdmin(handler)
	case RouteAuthTenant:
		return requireRuntimeTenant(handler)
	case RouteAuthService:
		return requireRuntimeService(handler)
	default:
		return requireRuntimeAdmin(handler)
	}
}

func requireRuntimeAdmin(handler http.HandlerFunc) http.HandlerFunc {
	adminKey := os.Getenv(helmauth.AdminAPIKeyEnv)
	return func(w http.ResponseWriter, r *http.Request) {
		principal, detail, ok := helmauth.AdminPrincipalFromRequest(r, adminKey)
		if !ok {
			api.WriteUnauthorized(w, detail)
			return
		}
		handler(w, r.WithContext(helmauth.WithPrincipal(r.Context(), principal)))
	}
}

func requireRuntimeTenant(handler http.HandlerFunc) http.HandlerFunc {
	adminKey := os.Getenv(helmauth.AdminAPIKeyEnv)
	return func(w http.ResponseWriter, r *http.Request) {
		adminPrincipal, detail, ok := helmauth.AdminPrincipalFromRequest(r, adminKey)
		if !ok {
			api.WriteUnauthorized(w, detail)
			return
		}

		tenantID := configuredRuntimeTenantID()
		if requestedTenantID := selectedTenantID(r); requestedTenantID != "" && requestedTenantID != tenantID {
			api.WriteForbidden(w, "Tenant-scoped route tenant mismatch")
			return
		}

		principalID := configuredRuntimePrincipalID(adminPrincipal)
		if principalID == "" {
			api.WriteForbidden(w, "Tenant-scoped route principal could not be resolved")
			return
		}
		if requestedPrincipalID := strings.TrimSpace(r.Header.Get(principalHeader)); requestedPrincipalID != "" && requestedPrincipalID != principalID {
			api.WriteForbidden(w, "Tenant-scoped route principal mismatch")
			return
		}
		principal := &helmauth.BasePrincipal{
			ID:       principalID,
			TenantID: tenantID,
			Roles:    append([]string(nil), adminPrincipal.GetRoles()...),
		}
		handler(w, r.WithContext(helmauth.WithPrincipal(r.Context(), principal)))
	}
}

func configuredRuntimeTenantID() string {
	if tenantID := strings.TrimSpace(os.Getenv(runtimeTenantIDEnv)); tenantID != "" {
		return tenantID
	}
	return defaultRuntimeTenantID
}

func configuredRuntimePrincipalID(adminPrincipal helmauth.Principal) string {
	if principalID := strings.TrimSpace(os.Getenv(runtimePrincipalIDEnv)); principalID != "" {
		return principalID
	}
	return strings.TrimSpace(adminPrincipal.GetID())
}

func requireRuntimeService(handler http.HandlerFunc) http.HandlerFunc {
	serviceKey := os.Getenv(serviceAPIKeyEnv)
	return func(w http.ResponseWriter, r *http.Request) {
		if serviceKey == "" {
			api.WriteUnauthorized(w, "Service API key not configured (set HELM_SERVICE_API_KEY)")
			return
		}
		token, detail, ok := helmauth.BearerToken(r)
		if !ok {
			api.WriteUnauthorized(w, detail)
			return
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(serviceKey)) != 1 {
			api.WriteUnauthorized(w, "Invalid service API key")
			return
		}

		principal := &helmauth.BasePrincipal{
			ID:       servicePrincipalID,
			TenantID: "system",
			Roles:    []string{"service"},
		}
		handler(w, r.WithContext(helmauth.WithPrincipal(r.Context(), principal)))
	}
}

func selectedTenantID(r *http.Request) string {
	if tenantID := strings.TrimSpace(r.Header.Get(tenantHeader)); tenantID != "" {
		return tenantID
	}
	return strings.TrimSpace(r.URL.Query().Get("tenant_id"))
}
