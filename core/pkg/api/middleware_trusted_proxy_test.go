package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func trustedProxyLimiter(t *testing.T, cidrs string) *GlobalRateLimiter {
	t.Helper()
	networks, err := ParseTrustedProxyCIDRs(cidrs)
	if err != nil {
		t.Fatalf("parse %q: %v", cidrs, err)
	}
	rl := &GlobalRateLimiter{
		visitors:      make(map[string]*visitor),
		actorVisitors: make(map[string]*visitor),
		config:        rateLimitConfig{rps: 1, burst: 1},
	}
	return rl.WithTrustedProxies(networks)
}

// S-09: a caller that connects directly must not choose its own bucket by
// rotating X-Real-IP or X-Forwarded-For. Before the fix, trusting proxy headers
// was a boolean, so every request with a fresh header value got a fresh bucket.
func TestRateLimiterIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	rl := trustedProxyLimiter(t, "10.20.0.0/16")
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	limited := 0
	for i := range 5 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/evaluate", nil)
		req.RemoteAddr = "203.0.113.7:4000"
		req.Header.Set("X-Real-IP", "198.51.100."+strconv.Itoa(i+1))
		req.Header.Set("X-Forwarded-For", "192.0.2."+strconv.Itoa(i+1))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited != 4 {
		t.Fatalf("rotating forwarded headers from an untrusted peer: %d of 5 requests limited, want 4 (one bucket for the peer)", limited)
	}
}

func TestRateLimiterClientIPHonoursOnlyTrustedProxies(t *testing.T) {
	tests := []struct {
		name       string
		cidrs      string
		remoteAddr string
		realIP     string
		forwarded  []string
		want       string
	}{
		{name: "no trusted proxies configured", remoteAddr: "10.20.1.1:1", realIP: "198.51.100.1", want: "10.20.1.1"},
		{name: "untrusted peer", cidrs: "10.20.0.0/16", remoteAddr: "203.0.113.7:1", realIP: "198.51.100.1", forwarded: []string{"198.51.100.2"}, want: "203.0.113.7"},
		{name: "trusted peer sets X-Real-IP", cidrs: "10.20.0.0/16", remoteAddr: "10.20.1.1:1", realIP: "198.51.100.1", want: "198.51.100.1"},
		{name: "trusted peer with malformed X-Real-IP falls back to forwarded chain", cidrs: "10.20.0.0/16", remoteAddr: "10.20.1.1:1", realIP: "not-an-ip", forwarded: []string{"198.51.100.3"}, want: "198.51.100.3"},
		// The leftmost X-Forwarded-For entry is whatever the client sent; the
		// client is the rightmost hop that is not one of our proxies.
		{name: "client-supplied leftmost entry is ignored", cidrs: "10.20.0.0/16", remoteAddr: "10.20.1.1:1", forwarded: []string{"192.0.2.99, 198.51.100.4, 10.20.3.3"}, want: "198.51.100.4"},
		{name: "multiple header lines", cidrs: "10.20.0.0/16,fd00::/8", remoteAddr: "[fd00::1]:1", forwarded: []string{"192.0.2.99", "198.51.100.5, fd00::2"}, want: "198.51.100.5"},
		{name: "chain of only trusted proxies keeps the peer", cidrs: "10.20.0.0/16", remoteAddr: "10.20.1.1:1", forwarded: []string{"10.20.2.2"}, want: "10.20.1.1"},
		{name: "malformed hop stops the walk at the peer", cidrs: "10.20.0.0/16", remoteAddr: "10.20.1.1:1", forwarded: []string{"198.51.100.6, garbage"}, want: "10.20.1.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rl := trustedProxyLimiter(t, test.cidrs)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = test.remoteAddr
			if test.realIP != "" {
				req.Header.Set("X-Real-IP", test.realIP)
			}
			for _, value := range test.forwarded {
				req.Header.Add("X-Forwarded-For", value)
			}
			if got := rl.clientIP(req); got != test.want {
				t.Fatalf("clientIP = %q, want %q", got, test.want)
			}
		})
	}
}

func TestParseTrustedProxyCIDRsRejectsMalformedEntries(t *testing.T) {
	for _, raw := range []string{"10.0.0.1", "10.0.0.0/33", "proxy.internal/24"} {
		if _, err := ParseTrustedProxyCIDRs(raw); err == nil {
			t.Fatalf("%q parsed; a trusted proxy must be an explicit CIDR", raw)
		}
	}
	networks, err := ParseTrustedProxyCIDRs(" 10.0.0.0/8, ,fd00::/8 ")
	if err != nil || len(networks) != 2 {
		t.Fatalf("networks=%v err=%v, want two networks with blank entries skipped", networks, err)
	}
}
