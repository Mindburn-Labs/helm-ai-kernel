package main

import (
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

// principalBindingStore is the package-level registry consulted by
// requireRuntimeTenant to accept (tenant, principal) pairs beyond the single
// env-configured pair. It is nil unless SetPrincipalBindingStore is called
// during server startup (see main.go registration), matching
// requireRuntimeTenant's existing pattern of reading global os.Getenv state.
// nil => env-pair-only behavior (current behavior, no panic).
var principalBindingStore store.PrincipalBindingStore

// SetPrincipalBindingStore injects the registry consulted by the tenant gate.
// Call once during server registration (guarded by services != nil); tests
// may call it with a fake/in-memory store and must reset it via
// SetPrincipalBindingStore(nil) in t.Cleanup.
func SetPrincipalBindingStore(s store.PrincipalBindingStore) {
	principalBindingStore = s
}

const (
	tenantHeader           = "X-Helm-Tenant-ID"
	principalHeader        = "X-Helm-Principal-ID"
	workspaceHeader        = "X-Helm-Workspace-ID"
	runtimeTenantIDEnv     = "HELM_RUNTIME_TENANT_ID"
	runtimePrincipalIDEnv  = "HELM_RUNTIME_PRINCIPAL_ID"
	runtimeWorkspaceIDEnv  = "HELM_RUNTIME_WORKSPACE_ID"
	quickstartExpiresAtEnv = "HELM_QUICKSTART_SESSION_EXPIRES_AT"
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
		if expired, configured := quickstartSessionExpired(time.Now()); configured && expired {
			api.WriteUnauthorized(w, "Local quickstart session expired")
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
		if expired, configured := quickstartSessionExpired(time.Now()); configured && expired {
			api.WriteUnauthorized(w, "Local quickstart session expired")
			return
		}

		tenantID := configuredRuntimeTenantID()
		requestedTenantID := selectedTenantID(r)
		if requestedTenantID == "" {
			api.WriteForbidden(w, "Tenant-scoped route requires explicit tenant binding")
			return
		}

		principalID := configuredRuntimePrincipalID(adminPrincipal)
		requestedPrincipalID := strings.TrimSpace(r.Header.Get(principalHeader))
		if requestedPrincipalID == "" {
			api.WriteForbidden(w, "Tenant-scoped route requires explicit principal binding")
			return
		}

		// env path first: no DB hit for the common single-tenant/quickstart case.
		envMatch := requestedTenantID == tenantID && principalID != "" && requestedPrincipalID == principalID
		registered := false
		if !envMatch && principalBindingStore != nil {
			ok, err := principalBindingStore.Exists(r.Context(), requestedTenantID, requestedPrincipalID)
			if err != nil {
				// Fail closed: a store error must not be treated as a match.
				log.Printf("[helm] principal binding lookup failed, denying tenant-scoped request: %v", err)
			} else {
				registered = ok
			}
		}
		if !envMatch && !registered {
			if requestedTenantID != tenantID {
				api.WriteForbidden(w, "Tenant-scoped route tenant mismatch")
				return
			}
			api.WriteForbidden(w, "Tenant-scoped route principal mismatch")
			return
		}

		principal := &helmauth.BasePrincipal{
			ID:       requestedPrincipalID,
			TenantID: requestedTenantID,
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

func configuredRuntimeWorkspaceID() string {
	return strings.TrimSpace(os.Getenv(runtimeWorkspaceIDEnv))
}

func quickstartSessionExpired(now time.Time) (bool, bool) {
	raw := strings.TrimSpace(os.Getenv(quickstartExpiresAtEnv))
	if raw == "" {
		return false, false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return true, true
	}
	return !now.UTC().Before(expiresAt.UTC()), true
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
