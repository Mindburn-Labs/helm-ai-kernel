package spendproxy

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// stockPost sends what a stock OpenAI client sends: a chat request with only
// an Authorization header.
func (f *proxyFixture) stockPost(t *testing.T, authorization, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.http.URL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (f *proxyFixture) get(t *testing.T, path, authorization string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.http.URL+path, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

const stockBody = `{"model":"base-model","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}`

// TestCallersModeServesAStockClient (helm-tracker#313 r2, finding 7): a stock
// OpenAI client with the caller token as its API key and no X-HELM header is
// served: the proxy mints an idempotency key when the request names none.
func TestCallersModeServesAStockClient(t *testing.T) {
	f := newProxyFixtureWithConfig(t, callerConfig())
	for i := range 2 {
		if status, body := f.stockPost(t, "Bearer "+callerTokenLive, stockBody); status != http.StatusOK {
			t.Fatalf("request %d: status %d (%s)", i, status, body)
		}
	}
	if f.upstream.calls.Load() != 2 {
		t.Fatalf("dispatches = %d, want two separate spends", f.upstream.calls.Load())
	}
}

// TestIdempotencyKeysAreScopedToTheCaller (finding 10): one caller's key
// neither blocks another caller's request nor tells it the key exists.
func TestIdempotencyKeysAreScopedToTheCaller(t *testing.T) {
	f := newProxyFixtureWithConfig(t, callerConfig())
	if status, body := f.callerPost(t, callerTokenReplay, "mini-model", "shared-key", map[string]string{inferencegateway.HeaderSpendEnvelope: "env-sub"}); status != http.StatusOK {
		t.Fatalf("the replay caller: status %d (%s)", status, body)
	}
	if status, body := f.callerPost(t, callerTokenLive, "base-model", "shared-key", nil); status != http.StatusOK {
		t.Fatalf("the live caller's own use of the key: status %d (%s)", status, body)
	}
	if f.upstream.calls.Load() != 2 {
		t.Fatalf("dispatches = %d, want one per caller", f.upstream.calls.Load())
	}
	// The same caller's identical retry is still answered from its first use.
	if status, body := f.callerPost(t, callerTokenLive, "base-model", "shared-key", nil); status != http.StatusOK || f.upstream.calls.Load() != 2 {
		t.Fatalf("the live caller's retry: status %d (%s), %d dispatches", status, body, f.upstream.calls.Load())
	}
}

// TestHealthAndModelsNeedTheCallerCredential (finding 13, mutant N16): with
// callers configured, /v1/models and /helm/spend/health need a configured
// token; without callers they are open.
func TestHealthAndModelsNeedTheCallerCredential(t *testing.T) {
	f := newProxyFixtureWithConfig(t, callerConfig())
	for _, path := range []string{"/v1/models", "/helm/spend/health"} {
		if status := f.get(t, path, ""); status != http.StatusUnauthorized {
			t.Errorf("%s without a token: %d, want 401", path, status)
		}
		if status := f.get(t, path, "Bearer "+callerTokenLive); status != http.StatusOK {
			t.Errorf("%s with a token: %d, want 200", path, status)
		}
	}
	open := newProxyFixture(t)
	for _, path := range []string{"/v1/models", "/helm/spend/health"} {
		if status := open.get(t, path, ""); status != http.StatusOK {
			t.Errorf("%s without callers: %d, want 200", path, status)
		}
	}
}

// TestBearerSchemeIsCaseInsensitive (finding 13): the authentication scheme
// is case-insensitive (RFC 7235), so "bearer" is a bearer.
func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	f := newProxyFixtureWithConfig(t, callerConfig())
	for _, scheme := range []string{"bearer", "BEARER", "Bearer"} {
		if status, body := f.stockPost(t, scheme+" "+callerTokenLive, stockBody); status != http.StatusOK {
			t.Errorf("scheme %q: status %d (%s)", scheme, status, body)
		}
	}
	if status, _ := f.stockPost(t, "Basic "+callerTokenLive, stockBody); status != http.StatusUnauthorized {
		t.Errorf("another scheme: status %d, want 401", status)
	}
}

// TestShortCallerTokensAreRefused (finding 13): a caller token is at least 32
// bytes, so a token whose SHA-256 the config holds cannot be guessed from it.
func TestShortCallerTokensAreRefused(t *testing.T) {
	short := "too-short-a-token"
	cfg := strings.Replace(callerConfig(), tokenHash(callerTokenLive), tokenHash(short), 1)
	f := newProxyFixtureWithConfig(t, cfg)
	status, body := f.stockPost(t, "Bearer "+short, stockBody)
	if status != http.StatusUnauthorized || !strings.Contains(body, "32") || f.upstream.calls.Load() != 0 {
		t.Fatalf("a %d-byte token: status %d (%s), %d dispatches; want 401 naming the 32-byte minimum", len(short), status, body, f.upstream.calls.Load())
	}
}
