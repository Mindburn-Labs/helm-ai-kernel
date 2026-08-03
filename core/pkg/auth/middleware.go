// quantum_posture: JWT validation here delegates signature verification to the
// injected identity.KeySet, so the algorithms in use are classical and are
// chosen by that provider rather than fixed in this file. Any hybrid or
// post-quantum migration lands in the key set, not in this middleware.

package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity"
	"github.com/golang-jwt/jwt/v5"
)

// JWTValidator validates JWT tokens and extracts claims.
type JWTValidator struct {
	// KeySet provides the keys for validation.
	KeySet identity.KeySet
}

// HelmClaims are the JWT claims expected by the HELM API.
type HelmClaims struct {
	jwt.RegisteredClaims
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
}

// NewJWTValidator creates a validator with the given KeySet.
func NewJWTValidator(ks identity.KeySet) *JWTValidator {
	if ks == nil {
		return nil
	}
	return &JWTValidator{KeySet: ks}
}

// Validate parses and validates a JWT token string.
func (v *JWTValidator) Validate(tokenStr string) (*HelmClaims, error) {
	if v.KeySet == nil {
		return nil, fmt.Errorf("validator uninitialized")
	}

	claims := &HelmClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, v.KeySet.KeyFunc())
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// publicPaths are endpoints that do not require authentication.
var publicPaths = []string{
	"/health",
	"/healthz",
	"/readiness",
	"/startup",
	"/version",
	"/v1/chat/completions",
	"/mcp",
	"/mcp/v1/capabilities",
	"/mcp/v1/execute",
	"/api/auth/login",
	"/api/auth/callback",
	"/api/signup",
	"/api/onboarding/verify",
	"/api/resend-verification",
}

// isPublicPath checks if the path should be accessible without auth.
func isPublicPath(path string) bool {
	if strings.HasPrefix(path, "/static/") {
		return true
	}
	for _, p := range publicPaths {
		if path == p {
			return true
		}
	}
	return false
}

// NewMiddleware creates JWT auth middleware.
// If validator is nil, all non-public requests are rejected (fail closed).
func NewMiddleware(validator *JWTValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Allow public paths
			if isPublicPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// 2. Extract Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httperr.WriteUnauthorized(w, "Missing Authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				httperr.WriteUnauthorized(w, "Invalid Authorization header format (expected 'Bearer <token>')")
				return
			}
			tokenStr := parts[1]

			// 3. Fail closed if no validator configured
			if validator == nil {
				httperr.WriteUnauthorized(w, "Authentication not configured")
				return
			}

			// 4. Validate JWT
			claims, err := validator.Validate(tokenStr)
			if err != nil {
				httperr.WriteUnauthorized(w, "Invalid or expired token")
				return
			}
			if claims.Subject == "" {
				httperr.WriteUnauthorized(w, "Token subject is required")
				return
			}
			if claims.TenantID == "" {
				httperr.WriteUnauthorized(w, "Token tenant binding is required")
				return
			}

			// 5. Build Principal from claims
			principal := &BasePrincipal{
				ID:       claims.Subject,
				TenantID: claims.TenantID,
				Roles:    claims.Roles,
			}

			// 6. Inject into context
			ctx := WithPrincipal(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Middleware is the legacy compatibility wrapper.
// Deprecated: Use NewMiddleware(validator) instead.
func Middleware(next http.Handler) http.Handler {
	// Legacy support is removed requiring KeySet injection.
	// This will panic if used, driving migration.
	panic("auth.Middleware is deprecated: use NewMiddleware(validator) with a KeySet")
}
