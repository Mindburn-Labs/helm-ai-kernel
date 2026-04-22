package auth

import (
	"net/http"
	"os"
	"strings"
)

// CORSMiddleware handles Cross-Origin Resource Sharing.
// Allowed origins are read from the CORS_ORIGINS env var (comma-separated).
// In development (no env var), defaults to allowing all origins.
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	if len(allowedOrigins) == 0 {
		// Read from environment
		if origins := os.Getenv("CORS_ORIGINS"); origins != "" {
			allowedOrigins = strings.Split(origins, ",")
			for i := range allowedOrigins {
				allowedOrigins[i] = strings.TrimSpace(allowedOrigins[i])
			}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if origin != "" {
				allowed := isOriginAllowed(origin, allowedOrigins)
				if allowed {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, X-Operator-ID")
			w.Header().Set("Access-Control-Expose-Headers", "Retry-After, X-Request-ID")
			w.Header().Set("Access-Control-Max-Age", "86400")

			// Handle preflight
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isOriginAllowed checks if the origin matches the allowed list.
// An empty list means all origins are allowed (development mode).
func isOriginAllowed(origin string, allowed []string) bool {
	if len(allowed) == 0 {
		return true // Dev mode: allow all
	}
	for _, a := range allowed {
		if a == "*" || a == origin {
			return true
		}
	}
	return false
}
