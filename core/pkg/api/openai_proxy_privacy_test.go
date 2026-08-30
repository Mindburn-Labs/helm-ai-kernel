package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIProxyProtectsRequestAndResponse(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-privacy","choices":[{"message":{"role":"assistant","content":"reply to person@example.com"}}]}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-test","messages":[{"role":"user","content":"contact person@example.com"}]}`))
	HandleOpenAIProxy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(upstreamBody, "person@example.com") || !strings.Contains(upstreamBody, "[REDACTED_EMAIL]") {
		t.Fatalf("upstream body was not protected: %s", upstreamBody)
	}
	if strings.Contains(rec.Body.String(), "person@example.com") || !strings.Contains(rec.Body.String(), "[REDACTED_EMAIL]") {
		t.Fatalf("response body was not protected: %s", rec.Body.String())
	}
}

func TestOpenAIProxyFailsClosedBeforeDispatch(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)

	for name, body := range map[string]string{
		"restricted": `{"model":"gpt-test","messages":[{"role":"user","content":"api_key=sk_live_example1234"}]}`,
		"stream":     `{"model":"gpt-test","stream":true,"messages":[{"role":"user","content":"hello"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			HandleOpenAIProxy(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body)))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("upstream calls = %d, want 0", calls)
	}
}
