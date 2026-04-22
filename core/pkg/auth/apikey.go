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

	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
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
	adminKey := os.Getenv("HELM_ADMIN_API_KEY")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fail-closed: no key configured means no access
			if adminKey == "" {
				api.WriteUnauthorized(w, "Admin API key not configured (set HELM_ADMIN_API_KEY)")
				return
			}

			// Extract Bearer token
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				api.WriteUnauthorized(w, "Missing Authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				api.WriteUnauthorized(w, "Invalid Authorization header format (expected 'Bearer <key>')")
				return
			}
			token := parts[1]

			// Constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(token), []byte(adminKey)) != 1 {
				api.WriteUnauthorized(w, "Invalid API key")
				return
			}

			// Inject admin principal into context
			principal := &BasePrincipal{
				ID:       "system-admin",
				TenantID: "system",
				Roles:    []string{"admin"},
			}
			ctx := WithPrincipal(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdminAuth wraps an http.HandlerFunc with API key authentication.
// Convenience helper for wrapping individual handler functions.
func RequireAdminAuth(handler http.HandlerFunc) http.Handler {
	return AdminAPIKeyMiddleware()(http.HandlerFunc(handler))
}
