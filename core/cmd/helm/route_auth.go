package main

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-oss/core/pkg/auth"
)

const (
	tenantHeader       = "X-Helm-Tenant-ID"
	principalHeader    = "X-Helm-Principal-ID"
	serviceAPIKeyEnv   = "HELM_SERVICE_API_KEY"
	servicePrincipalID = "service-internal"
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

		tenantID := selectedTenantID(r)
		if tenantID == "" {
			api.WriteForbidden(w, "Tenant-scoped route requires X-Helm-Tenant-ID header or tenant_id query parameter")
			return
		}

		principalID := strings.TrimSpace(r.Header.Get(principalHeader))
		if principalID == "" {
			principalID = adminPrincipal.GetID()
		}
		principal := &helmauth.BasePrincipal{
			ID:       principalID,
			TenantID: tenantID,
			Roles:    append([]string(nil), adminPrincipal.GetRoles()...),
		}
		handler(w, r.WithContext(helmauth.WithPrincipal(r.Context(), principal)))
	}
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
