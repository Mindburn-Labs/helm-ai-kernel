package main

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

// principalBindingStore is the package-level registry consulted by tenant and
// organization-runtime gates to accept (tenant, principal) pairs beyond the
// single env-configured pair. It is nil unless SetPrincipalBindingStore is called
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
	tenantHeader                 = "X-Helm-Tenant-ID"
	principalHeader              = "X-Helm-Principal-ID"
	workspaceHeader              = "X-Helm-Workspace-ID"
	runtimeAPIKeyHeader          = "X-HELM-API-Key"
	runtimeTenantIDEnv           = "HELM_RUNTIME_TENANT_ID"
	runtimePrincipalIDEnv        = "HELM_RUNTIME_PRINCIPAL_ID"
	runtimeWorkspaceIDEnv        = "HELM_RUNTIME_WORKSPACE_ID"
	quickstartExpiresAtEnv       = "HELM_QUICKSTART_SESSION_EXPIRES_AT"
	defaultRuntimeTenantID       = "default"
	serviceAPIKeyEnv             = "HELM_SERVICE_API_KEY"
	servicePrincipalID           = "service-internal"
	organizationRuntimeAPIKeyEnv = "HELM_ORGANIZATION_RUNTIME_API_KEY"
	organizationRuntimeRole      = "organization-runtime"
)

func protectRuntimeHandler(auth RouteAuth, handler http.HandlerFunc) http.HandlerFunc {
	switch auth {
	case RouteAuthPublic:
		return handler
	case RouteAuthAdmin, RouteAuthAuthenticated:
		return requireRuntimeAdmin(handler)
	case RouteAuthTenant:
		return requireRuntimeTenant(handler)
	case RouteAuthOrganizationRuntime:
		return requireRuntimeOrganizationRuntime(handler)
	case RouteAuthConfiguredTenant:
		return requireRuntimeConfiguredTenant(handler)
	case RouteAuthService:
		return requireRuntimeService(handler)
	default:
		return requireRuntimeAdmin(handler)
	}
}

func configuredOrganizationRuntimeAPIKey() (string, error) {
	raw := os.Getenv(organizationRuntimeAPIKeyEnv)
	if raw == "" {
		return "", nil
	}
	key := strings.TrimSpace(raw)
	if key == "" || raw != key || len(key) > 4096 || strings.IndexFunc(key, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%s must be a non-empty credential without surrounding whitespace or control characters", organizationRuntimeAPIKeyEnv)
	}
	if key == strings.TrimSpace(os.Getenv(helmauth.AdminAPIKeyEnv)) || key == strings.TrimSpace(os.Getenv(serviceAPIKeyEnv)) {
		return "", fmt.Errorf("%s must be distinct from other runtime credentials", organizationRuntimeAPIKeyEnv)
	}
	return key, nil
}

func requireRuntimeOrganizationRuntime(handler http.HandlerFunc) http.HandlerFunc {
	organizationRuntimeKey, configErr := configuredOrganizationRuntimeAPIKey()
	return func(w http.ResponseWriter, r *http.Request) {
		if configErr != nil || organizationRuntimeKey == "" {
			httperr.WriteUnauthorized(w, "Organization runtime credential is unavailable")
			return
		}
		token, detail, ok := helmauth.BearerToken(r)
		if !ok {
			httperr.WriteUnauthorized(w, detail)
			return
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(organizationRuntimeKey)) != 1 {
			httperr.WriteUnauthorized(w, "Invalid organization runtime credential")
			return
		}

		tenantID := strings.TrimSpace(r.Header.Get(tenantHeader))
		principalID := strings.TrimSpace(r.Header.Get(principalHeader))
		workspaceID := strings.TrimSpace(r.Header.Get(workspaceHeader))
		if tenantID == "" || principalID == "" || workspaceID == "" {
			api.WriteForbidden(w, "Organization runtime route requires explicit tenant, principal, and workspace bindings")
			return
		}
		configuredTenantID := strings.TrimSpace(os.Getenv(runtimeTenantIDEnv))
		configuredPrincipalID := strings.TrimSpace(os.Getenv(runtimePrincipalIDEnv))
		envMatch := configuredTenantID != "" && configuredPrincipalID != "" && tenantID == configuredTenantID && principalID == configuredPrincipalID
		registered := false
		if !envMatch && principalBindingStore != nil {
			var err error
			registered, err = principalBindingStore.Exists(r.Context(), tenantID, principalID)
			if err != nil {
				slog.ErrorContext(r.Context(), "principal binding lookup failed, denying organization runtime request", "error", err)
				api.WriteForbidden(w, "Organization runtime principal binding could not be verified")
				return
			}
		}
		if !envMatch && !registered {
			api.WriteForbidden(w, "Organization runtime principal is not registered for the tenant")
			return
		}

		principal := &helmauth.BasePrincipal{
			ID:       principalID,
			TenantID: tenantID,
			Roles:    []string{organizationRuntimeRole},
		}
		ctx := helmauth.WithPrincipal(r.Context(), principal)
		ctx = helmauth.WithAuthenticatedCredential(ctx, token)
		handler(w, r.WithContext(ctx))
	}
}

// requireRuntimeConfiguredTenant authenticates the standalone control key and
// binds the one server-configured tenant/principal pair. Optional identity
// headers are assertions only: when present they must match the configured
// values exactly, so callers cannot select a different Guardian identity.
func requireRuntimeConfiguredTenant(handler http.HandlerFunc) http.HandlerFunc {
	adminKey := os.Getenv(helmauth.AdminAPIKeyEnv)
	return func(w http.ResponseWriter, r *http.Request) {
		token, detail, ok := runtimeCredentialToken(r)
		if !ok {
			httperr.WriteUnauthorized(w, detail)
			return
		}
		adminPrincipal, detail, ok := helmauth.AdminPrincipalFromToken(token, adminKey)
		if !ok {
			httperr.WriteUnauthorized(w, detail)
			return
		}
		if expired, configured := quickstartSessionExpired(time.Now()); configured && expired {
			httperr.WriteUnauthorized(w, "Local quickstart session expired")
			return
		}
		tenantID := configuredRuntimeTenantID()
		principalID := configuredRuntimePrincipalID(adminPrincipal)
		if requested := selectedTenantID(r); requested != "" && requested != tenantID {
			api.WriteForbidden(w, "Configured tenant route tenant mismatch")
			return
		}
		if requested := strings.TrimSpace(r.Header.Get(principalHeader)); requested != "" && requested != principalID {
			api.WriteForbidden(w, "Configured tenant route principal mismatch")
			return
		}

		principal := &helmauth.BasePrincipal{
			ID:       principalID,
			TenantID: tenantID,
			Roles:    append([]string(nil), adminPrincipal.GetRoles()...),
		}
		ctx := helmauth.WithPrincipal(r.Context(), principal)
		ctx = helmauth.WithAuthenticatedCredential(ctx, token)
		handler(w, r.WithContext(ctx))
	}
}

func requireRuntimeAdmin(handler http.HandlerFunc) http.HandlerFunc {
	adminKey := os.Getenv(helmauth.AdminAPIKeyEnv)
	return func(w http.ResponseWriter, r *http.Request) {
		token, detail, ok := helmauth.BearerToken(r)
		if !ok {
			httperr.WriteUnauthorized(w, detail)
			return
		}
		principal, detail, ok := helmauth.AdminPrincipalFromToken(token, adminKey)
		if !ok {
			httperr.WriteUnauthorized(w, detail)
			return
		}
		if expired, configured := quickstartSessionExpired(time.Now()); configured && expired {
			httperr.WriteUnauthorized(w, "Local quickstart session expired")
			return
		}
		ctx := helmauth.WithPrincipal(r.Context(), principal)
		ctx = helmauth.WithAuthenticatedCredential(ctx, token)
		handler(w, r.WithContext(ctx))
	}
}

func requireRuntimeTenant(handler http.HandlerFunc) http.HandlerFunc {
	adminKey := os.Getenv(helmauth.AdminAPIKeyEnv)
	return func(w http.ResponseWriter, r *http.Request) {
		token, detail, ok := helmauth.BearerToken(r)
		if !ok {
			httperr.WriteUnauthorized(w, detail)
			return
		}
		adminPrincipal, detail, ok := helmauth.AdminPrincipalFromToken(token, adminKey)
		if !ok {
			httperr.WriteUnauthorized(w, detail)
			return
		}
		if expired, configured := quickstartSessionExpired(time.Now()); configured && expired {
			httperr.WriteUnauthorized(w, "Local quickstart session expired")
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
				// Logged with the request context so the denial carries
				// trace_id/span_id and can be joined to its server span.
				slog.ErrorContext(r.Context(), "principal binding lookup failed, denying tenant-scoped request", "error", err)
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
		ctx := helmauth.WithPrincipal(r.Context(), principal)
		ctx = helmauth.WithAuthenticatedCredential(ctx, token)
		handler(w, r.WithContext(ctx))
	}
}

func runtimeCredentialToken(r *http.Request) (string, string, bool) {
	if token := r.Header.Get(runtimeAPIKeyHeader); strings.TrimSpace(token) != "" {
		return token, "", true
	}
	return helmauth.BearerToken(r)
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
			httperr.WriteUnauthorized(w, "Service API key not configured (set HELM_SERVICE_API_KEY)")
			return
		}
		token, detail, ok := helmauth.BearerToken(r)
		if !ok {
			httperr.WriteUnauthorized(w, detail)
			return
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(serviceKey)) != 1 {
			httperr.WriteUnauthorized(w, "Invalid service API key")
			return
		}

		principal := &helmauth.BasePrincipal{
			ID:       servicePrincipalID,
			TenantID: helmauth.SystemTenantID,
			Roles:    []string{"service"},
		}
		ctx := helmauth.WithPrincipal(r.Context(), principal)
		ctx = helmauth.WithAuthenticatedCredential(ctx, token)
		handler(w, r.WithContext(ctx))
	}
}

func selectedTenantID(r *http.Request) string {
	if tenantID := strings.TrimSpace(r.Header.Get(tenantHeader)); tenantID != "" {
		return tenantID
	}
	return strings.TrimSpace(r.URL.Query().Get("tenant_id"))
}
