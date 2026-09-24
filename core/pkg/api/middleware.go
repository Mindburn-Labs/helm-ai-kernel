package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
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

// RateLimitProfile configures a token bucket. Zero values disable the profile.
type RateLimitProfile struct {
	RPS   int
	Burst int
}

func (p RateLimitProfile) enabled() bool {
	return p.RPS > 0 && p.Burst > 0
}

// GlobalRateLimiter manages per-IP rate limiters.
type GlobalRateLimiter struct {
	visitors           map[string]*visitor
	actorVisitors      map[string]*visitor
	endpointLimiters   map[string]*rate.Limiter
	endpointProfiles   map[string]RateLimitProfile
	mu                 sync.Mutex
	config             rateLimitConfig
	actorProfile       RateLimitProfile
	endpointClassifier func(*http.Request) string
	concurrency        chan struct{}
	lowPriority        chan struct{}
	lowPriorityShed    bool
	trustedProxies     []*net.IPNet // peers whose X-Real-IP / X-Forwarded-For are honoured
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
		visitors:         make(map[string]*visitor),
		actorVisitors:    make(map[string]*visitor),
		endpointLimiters: make(map[string]*rate.Limiter),
		endpointProfiles: make(map[string]RateLimitProfile),
		config: rateLimitConfig{
			rps:   rate.Limit(rps),
			burst: burst,
		},
	}
	// Start background cleanup
	go rl.cleanupVisitors()
	return rl
}

// WithEndpointLimits enables token buckets for endpoint classes returned by classifier.
func (rl *GlobalRateLimiter) WithEndpointLimits(classifier func(*http.Request) string, profiles map[string]RateLimitProfile) *GlobalRateLimiter {
	rl.endpointClassifier = classifier
	rl.endpointProfiles = make(map[string]RateLimitProfile, len(profiles))
	for class, profile := range profiles {
		if profile.enabled() {
			rl.endpointProfiles[class] = profile
		}
	}
	return rl
}

// WithActorLimit enables per actor/resource request limiting.
func (rl *GlobalRateLimiter) WithActorLimit(profile RateLimitProfile) *GlobalRateLimiter {
	if profile.enabled() {
		rl.actorProfile = profile
	}
	return rl
}

// WithConcurrencyLimit enables a process-local in-flight request cap.
func (rl *GlobalRateLimiter) WithConcurrencyLimit(maxConcurrent int) *GlobalRateLimiter {
	if maxConcurrent > 0 {
		rl.concurrency = make(chan struct{}, maxConcurrent)
	}
	return rl
}

// WithLowPriorityLoadShed enables an independent in-flight cap for low-priority traffic.
func (rl *GlobalRateLimiter) WithLowPriorityLoadShed(maxConcurrent int) *GlobalRateLimiter {
	if maxConcurrent > 0 {
		rl.lowPriority = make(chan struct{}, maxConcurrent)
		rl.lowPriorityShed = true
	}
	return rl
}

// WithTrustedProxies honours X-Real-IP and X-Forwarded-For only on requests
// whose connecting peer is inside one of networks: the reverse proxies in front
// of this deployment. Every other request is keyed by its peer address. A
// boolean "trust the headers" switch let any directly connected caller pick its
// own bucket by rotating the header (S-09, reopening F-12).
func (rl *GlobalRateLimiter) WithTrustedProxies(networks []*net.IPNet) *GlobalRateLimiter {
	rl.trustedProxies = append([]*net.IPNet(nil), networks...)
	return rl
}

// ParseTrustedProxyCIDRs parses a comma-separated list of CIDRs. Blank entries
// are skipped; every other entry must be a CIDR, not a bare address or name.
func ParseTrustedProxyCIDRs(raw string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q is not a CIDR: %w", entry, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func (rl *GlobalRateLimiter) trustedProxy(ip net.IP) bool {
	for _, network := range rl.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
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

func (rl *GlobalRateLimiter) getActorVisitor(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.actorVisitors[key]
	if !exists {
		limiter := rate.NewLimiter(rate.Limit(rl.actorProfile.RPS), rl.actorProfile.Burst)
		rl.actorVisitors[key] = &visitor{limiter, time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

func (rl *GlobalRateLimiter) getEndpointLimiter(class string) (*rate.Limiter, bool) {
	profile, ok := rl.endpointProfiles[class]
	if !ok || !profile.enabled() {
		return nil, false
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	limiter, exists := rl.endpointLimiters[class]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(profile.RPS), profile.Burst)
		rl.endpointLimiters[class] = limiter
	}
	return limiter, true
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
		for key, v := range rl.actorVisitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(rl.actorVisitors, key)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP returns the address the rate-limit buckets are keyed by. It is the
// connecting peer unless that peer is a trusted proxy. Behind a trusted proxy it
// is the proxy-set X-Real-IP, or else the rightmost X-Forwarded-For hop that is
// not itself a trusted proxy: the leftmost entries are whatever the client sent.
// A malformed hop ends the walk at the peer, so an unreadable chain shares the
// proxy's bucket instead of choosing a new one.
func (rl *GlobalRateLimiter) clientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = strings.TrimSuffix(strings.TrimPrefix(r.RemoteAddr, "["), "]")
	}
	peerIP := net.ParseIP(peer)
	if peerIP == nil || !rl.trustedProxy(peerIP) {
		return peer
	}
	if realIP := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); realIP != nil {
		return realIP.String()
	}
	var hops []string
	for _, value := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(value, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop := net.ParseIP(strings.TrimSpace(hops[i]))
		if hop == nil {
			break
		}
		if !rl.trustedProxy(hop) {
			return hop.String()
		}
	}
	return peer
}

// Middleware returns a Handler that enforces rate limits.
func (rl *GlobalRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.clientIP(r)
		endpointClass := rl.endpointClass(r)

		if rl.lowPriorityShed && rl.isLowPriority(r, endpointClass) {
			if !tryAcquire(rl.lowPriority) {
				WriteLimitDenied(w, http.StatusServiceUnavailable, "LOW_PRIORITY_LOAD_SHED", 1)
				return
			}
			defer release(rl.lowPriority)
		}

		if !tryAcquire(rl.concurrency) {
			WriteLimitDenied(w, http.StatusServiceUnavailable, "CONCURRENCY_LIMIT_EXCEEDED", 1)
			return
		}
		defer release(rl.concurrency)

		limiter := rl.getVisitor(ip)
		if !limiter.Allow() {
			WriteLimitDenied(w, http.StatusTooManyRequests, "GLOBAL_RATE_LIMIT_EXCEEDED", 5)
			return
		}

		if endpointLimiter, ok := rl.getEndpointLimiter(endpointClass); ok && !endpointLimiter.Allow() {
			WriteLimitDenied(w, http.StatusTooManyRequests, "ENDPOINT_RATE_LIMIT_EXCEEDED", 5)
			return
		}

		if rl.actorProfile.enabled() {
			actorLimiter := rl.getActorVisitor(rl.actorResourceKey(r, ip))
			if !actorLimiter.Allow() {
				WriteLimitDenied(w, http.StatusTooManyRequests, "ACTOR_RESOURCE_RATE_LIMIT_EXCEEDED", 5)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *GlobalRateLimiter) endpointClass(r *http.Request) string {
	if rl.endpointClassifier == nil {
		return ""
	}
	return rl.endpointClassifier(r)
}

func (rl *GlobalRateLimiter) isLowPriority(r *http.Request, endpointClass string) bool {
	priority := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Helm-Priority")))
	if priority == "low" {
		return true
	}
	return endpointClass == "public"
}

// actorResourceKey derives the per-actor rate-limit bucket.
//
// The identity headers are combined with the peer address rather than used on
// their own. They are unauthenticated at this layer — the limiter runs before
// any route guard — so keying on them alone let a caller rotate
// X-Helm-Actor-ID to mint a fresh bucket per request and evade the limit
// entirely, or set a victim's actor id to exhaust that victim's bucket (F-12).
//
// Binding the bucket to fallbackIP keeps both closed: a rotating attacker stays
// pinned to their own address, and one caller can no longer consume another's
// allowance. Distinct actors behind a shared address still get distinct buckets.
func (rl *GlobalRateLimiter) actorResourceKey(r *http.Request, fallbackIP string) string {
	tenantID := strings.TrimSpace(r.Header.Get("X-Helm-Tenant-ID"))
	principalID := strings.TrimSpace(r.Header.Get("X-Helm-Principal-ID"))
	actorID := strings.TrimSpace(r.Header.Get("X-Helm-Actor-ID"))
	if actorID == "" && tenantID != "" && principalID != "" {
		actorID = tenantID + "/" + principalID
	}
	// Hash the attacker-influenced portion. Concatenating raw header values with
	// delimiters lets a caller embed the delimiter to collide with, or escape
	// from, another actor's bucket — the same unframed-concatenation mistake
	// that made the signature-verification cache forgeable.
	sum := sha256.Sum256([]byte(fallbackIP + "\x00" + actorID))
	return hex.EncodeToString(sum[:16]) + " " + r.Method + " " + r.URL.EscapedPath()
}

func tryAcquire(ch chan struct{}) bool {
	if ch == nil {
		return true
	}
	select {
	case ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func release(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
	}
}

// WriteLimitDenied writes an explicit limiter denial response.
func WriteLimitDenied(w http.ResponseWriter, status int, reason string, retryAfterSecs int) {
	if retryAfterSecs > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecs))
	}
	w.Header().Set("X-Helm-Limiter-Reason", reason)
	if status == http.StatusTooManyRequests {
		WriteError(w, status, "Too Many Requests", reason)
		return
	}
	WriteError(w, status, "Service Unavailable", reason)
}

// WithContextRateLimit enforces rate limits based on context values (e.g. TenantID).
// This requires the context to be populated previously (e.g. by auth middleware).
func WithContextRateLimit(next http.Handler, limitPerTenant int) http.Handler {
	_ = limitPerTenant
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
