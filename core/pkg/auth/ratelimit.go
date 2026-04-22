package auth

import (
	"fmt"
	"net/http"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel"
)

// RateLimitMiddleware enforces per-actor rate limiting at the HTTP layer.
// It extracts the actor ID from the authenticated Principal (falls back to remote IP).
// On rate limit exceeded, it returns 429 with a Retry-After header.
func RateLimitMiddleware(store kernel.LimiterStore, policy kernel.BackpressurePolicy) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fail open if no store configured (dev mode)
			if store == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Determine actor ID
			actorID := r.RemoteAddr
			if principal, err := GetPrincipal(r.Context()); err == nil {
				actorID = fmt.Sprintf("%s/%s", principal.GetTenantID(), principal.GetID())
			}

			// Check rate limit
			allowed, err := store.Allow(r.Context(), actorID, policy, 1)
			if err != nil {
				// Fail open on limiter errors to avoid blocking all traffic
				next.ServeHTTP(w, r)
				return
			}

			if !allowed {
				retryAfter := 60 / policy.RPM
				if retryAfter < 1 {
					retryAfter = 1
				}
				api.WriteTooManyRequests(w, retryAfter)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
