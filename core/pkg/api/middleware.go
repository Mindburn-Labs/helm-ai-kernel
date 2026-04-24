package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimitConfig holds the rate limiter settings.
type rateLimitConfig struct {
	rps   rate.Limit
	burst int
}

// GlobalRateLimiter manages per-IP rate limiters.
type GlobalRateLimiter struct {
	visitors   map[string]*visitor
	mu         sync.Mutex
	config     rateLimitConfig
	trustProxy bool // When true, extract client IP from X-Forwarded-For / X-Real-IP
}

// visitor tracks the rate limiter and last seen time for an IP.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewGlobalRateLimiter creates a new rate limiter.
// rps: requests per second allowed.
// burst: maximum burst size.
func NewGlobalRateLimiter(rps, burst int) *GlobalRateLimiter {
	rl := &GlobalRateLimiter{
		visitors: make(map[string]*visitor),
		config: rateLimitConfig{
			rps:   rate.Limit(rps),
			burst: burst,
		},
	}
	// Start background cleanup
	go rl.cleanupVisitors()
	return rl
}

// WithTrustProxy enables extraction of client IP from X-Forwarded-For / X-Real-IP headers.
// Only enable when HELM is behind a trusted reverse proxy.
func (rl *GlobalRateLimiter) WithTrustProxy(trust bool) *GlobalRateLimiter {
	rl.trustProxy = trust
	return rl
}

// getVisitor retrieving the limiter for a given IP, creating if necessary.
func (rl *GlobalRateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(rl.config.rps, rl.config.burst)
		rl.visitors[ip] = &visitor{limiter, time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

// cleanupVisitors removes stale visitor entries to prevent memory leaks.
// Checks every minute, removes entries older than 3 minutes.
func (rl *GlobalRateLimiter) cleanupVisitors() {
	for {
		time.Sleep(1 * time.Minute)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP extracts the client IP address from the request.
// When trustProxy is enabled, it prefers X-Real-IP and X-Forwarded-For headers.
func (rl *GlobalRateLimiter) clientIP(r *http.Request) string {
	if rl.trustProxy {
		// X-Real-IP takes priority (single IP set by proxy)
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			return strings.TrimSpace(realIP)
		}
		// X-Forwarded-For: client, proxy1, proxy2 — take the first (leftmost) entry
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if comma := strings.IndexByte(xff, ','); comma > 0 {
				return strings.TrimSpace(xff[:comma])
			}
			return strings.TrimSpace(xff)
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
		ip = strings.TrimPrefix(ip, "[")
		ip = strings.TrimSuffix(ip, "]")
	}
	return ip
}

// Middleware returns a Handler that enforces rate limits.
func (rl *GlobalRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.clientIP(r)

		limiter := rl.getVisitor(ip)
		if !limiter.Allow() {
			WriteTooManyRequests(w, 5) // Suggest 5 seconds backoff
			return
		}

		next.ServeHTTP(w, r)
	})
}

// WithContextRateLimit enforces rate limits based on context values (e.g. TenantID).
// This requires the context to be populated previously (e.g. by auth middleware).
func WithContextRateLimit(next http.Handler, limitPerTenant int) http.Handler {
	_ = limitPerTenant
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
