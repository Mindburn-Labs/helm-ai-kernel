package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── Server & Handlers ───────────────────────────────────────────

// ── Middleware ───────────────────────────────────────────────────

func TestRateLimiter_TrustProxy_XRealIP(t *testing.T) {
	rl := &GlobalRateLimiter{
		visitors: make(map[string]*visitor),
		config:   rateLimitConfig{rps: 100, burst: 100},
	}
	_, proxies, _ := net.ParseCIDR("10.0.0.0/8")
	rl.WithTrustedProxies([]*net.IPNet{proxies})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.RemoteAddr = "10.0.0.1:9999"
	ip := rl.clientIP(req)
	if ip != "1.2.3.4" {
		t.Errorf("expected X-Real-IP 1.2.3.4, got %s", ip)
	}
}

func TestRateLimiter_DefaultIgnoresProxyHeaders(t *testing.T) {
	rl := &GlobalRateLimiter{
		visitors: make(map[string]*visitor),
		config:   rateLimitConfig{rps: 100, burst: 100},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header.Set("X-Forwarded-For", "5.6.7.8")
	req.RemoteAddr = "10.0.0.1:9999"

	ip := rl.clientIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected remote address 10.0.0.1 when proxy headers are not trusted, got %s", ip)
	}
}

func TestRateLimiter_TrustProxy_XFF(t *testing.T) {
	rl := &GlobalRateLimiter{
		visitors: make(map[string]*visitor),
		config:   rateLimitConfig{rps: 100, burst: 100},
	}
	proxies, err := ParseTrustedProxyCIDRs("192.0.2.0/24,10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	rl.WithTrustedProxies(proxies)
	req := httptest.NewRequest(http.MethodGet, "/", nil) // peer 192.0.2.1
	req.Header.Set("X-Forwarded-For", "5.6.7.8, 10.0.0.1")
	ip := rl.clientIP(req)
	if ip != "5.6.7.8" {
		t.Errorf("expected rightmost untrusted XFF hop 5.6.7.8, got %s", ip)
	}
}

func TestRateLimiter_WithTrustedProxies(t *testing.T) {
	rl := &GlobalRateLimiter{visitors: make(map[string]*visitor), config: rateLimitConfig{rps: 10, burst: 10}}
	_, proxies, _ := net.ParseCIDR("10.0.0.0/8")
	rl.WithTrustedProxies([]*net.IPNet{proxies})
	if !rl.trustedProxy(net.ParseIP("10.1.2.3")) || rl.trustedProxy(net.ParseIP("192.0.2.1")) {
		t.Error("WithTrustedProxies should trust exactly the configured networks")
	}
}

// ── Memory Service ──────────────────────────────────────────────

func TestMemoryService_IngestReturnsError(t *testing.T) {
	svc := NewMemoryService()
	_, err := svc.Ingest(nil, IngestRequest{TenantID: "t", SourceID: "s"})
	if err == nil {
		t.Error("expected error from fake ingestion")
	}
}

func TestMemoryService_SearchReturnsQueryID(t *testing.T) {
	svc := NewMemoryService()
	res, err := svc.Search(nil, "test", "t1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.QueryID == "" {
		t.Error("expected non-empty QueryID")
	}
}

func TestHandleIngest_MethodNotAllowed(t *testing.T) {
	svc := NewMemoryService()
	req := httptest.NewRequest(http.MethodGet, "/memory/ingest", nil)
	w := httptest.NewRecorder()
	svc.HandleIngest(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleIngest_MissingFields(t *testing.T) {
	svc := NewMemoryService()
	body, _ := json.Marshal(IngestRequest{})
	req := httptest.NewRequest(http.MethodPost, "/memory/ingest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	svc.HandleIngest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSearch_MethodNotAllowed(t *testing.T) {
	svc := NewMemoryService()
	req := httptest.NewRequest(http.MethodGet, "/memory/search", nil)
	w := httptest.NewRecorder()
	svc.HandleSearch(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ── InMemoryDecisionStore ───────────────────────────────────────

func TestOpenAIProxy_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	w := httptest.NewRecorder()
	HandleOpenAIProxy(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestOpenAIProxy_InvalidBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(`not json`)))
	w := httptest.NewRecorder()
	HandleOpenAIProxy(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestOpenAIProxy_NoUpstream(t *testing.T) {
	t.Setenv("HELM_UPSTREAM_URL", "")
	body, _ := json.Marshal(OpenAIChatRequest{Model: "gpt-6-sol", Messages: []OpenAIMessage{{Role: "user", Content: "hi"}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	w := httptest.NewRecorder()
	HandleOpenAIProxy(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// fake to avoid importing contracts
type contracts_fake_decision struct {
	RequestID string
}
