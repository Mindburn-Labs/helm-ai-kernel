// quantum_posture: this path performs no signature verification. The shared
// admin key is compared with crypto/subtle.ConstantTimeCompare, a symmetric
// secret comparison with no public-key algorithm to migrate; the JWT mention
// below is describing the alternative mechanism, not using one.
//
// Package auth — apikey.go provides pre-shared API key authentication middleware.
//
// This is the recommended auth mechanism for OSS standalone deployments without
// full JWT infrastructure. Set HELM_ADMIN_API_KEY env var to enable.
// If unset, all protected endpoints are rejected (fail-closed).
package auth

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
)

const (
	// AdminAPIKeyEnv is the environment variable used by standalone OSS admin authentication.
	AdminAPIKeyEnv = "HELM_ADMIN_API_KEY"
	// SystemTenantID identifies HELM's non-customer admin/service boundary.
	SystemTenantID = "system"

	systemAdminPrincipalID = "system-admin"
)

// AdminAPIKeyMiddleware creates middleware that validates requests against a
// pre-shared API key from the HELM_ADMIN_API_KEY environment variable.
//
// Auth flow:
//  1. Read HELM_ADMIN_API_KEY at creation time (immutable after start)
//  2. If unset, ALL requests to protected endpoints are rejected (fail-closed)
//  3. Extract Bearer token from Authorization header
//  4. Constant-time compare against the pre-shared key
//  5. Inject a system admin principal into context on success
//
// Usage:
//
//	protectedHandler := auth.AdminAPIKeyMiddleware()(myHandler)
func AdminAPIKeyMiddleware() func(http.Handler) http.Handler {
	adminKey := os.Getenv(AdminAPIKeyEnv)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, detail, ok := BearerToken(r)
			if !ok {
				httperr.WriteUnauthorized(w, detail)
				return
			}
			principal, detail, ok := AdminPrincipalFromToken(token, adminKey)
			if !ok {
				httperr.WriteUnauthorized(w, detail)
				return
			}
			ctx := WithPrincipal(r.Context(), principal)
			ctx = WithAuthenticatedCredential(ctx, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdminAuth wraps an http.HandlerFunc with API key authentication.
// Convenience helper for wrapping individual handler functions.
func RequireAdminAuth(handler http.HandlerFunc) http.Handler {
	return AdminAPIKeyMiddleware()(http.HandlerFunc(handler))
}

// BearerToken extracts a case-sensitive Bearer token from an Authorization header.
func BearerToken(r *http.Request) (string, string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", "Missing Authorization header", false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", "Invalid Authorization header format (expected 'Bearer <key>')", false
	}
	if strings.TrimSpace(parts[1]) == "" {
		return "", "Missing bearer token", false
	}
	return parts[1], "", true
}

// AdminPrincipalFromRequest validates the configured admin key and returns the
// standalone system admin principal. An empty configured key fails closed.
func AdminPrincipalFromRequest(r *http.Request, adminKey string) (*BasePrincipal, string, bool) {
	token, detail, ok := BearerToken(r)
	if !ok {
		return nil, detail, false
	}
	return AdminPrincipalFromToken(token, adminKey)
}

// AdminPrincipalFromToken validates an already-extracted admin credential.
// Transport adapters use this when Authorization belongs to a downstream
// protocol and the HELM control credential is carried in a separate header.
func AdminPrincipalFromToken(token, adminKey string) (*BasePrincipal, string, bool) {
	if adminKey == "" {
		return nil, "Admin API key not configured (set HELM_ADMIN_API_KEY)", false
	}

	if subtle.ConstantTimeCompare([]byte(token), []byte(adminKey)) != 1 {
		return nil, "Invalid API key", false
	}

	return &BasePrincipal{
		ID:       systemAdminPrincipalID,
		TenantID: SystemTenantID,
		Roles:    []string{"admin"},
	}, "", true
}
