package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExecuteOllamaDiscoversDigestAndCallsAPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "0.5.0"})
	})
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []map[string]string{{"name": "test-model", "digest": "sha256:abc"}}})
	})
	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"message": map[string]string{"content": "ok"}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := NewGatewayRouter()
	if err := r.RouteWithConfig(context.Background(), RouteConfig{Provider: ProviderOllama, BaseURL: srv.URL, ModelName: "test-model"}); err != nil {
		t.Fatal(err)
	}
	res, err := r.Execute(context.Background(), ExecContext{Prompt: "hello", JSONMode: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "ok" || res.ModelHash != "sha256:abc" || res.RuntimeVersion != "0.5.0" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestExecuteOpenAICompatibleRequiresModelHash(t *testing.T) {
	srv := newOpenAICompatibleServer(t, "server-version")
	defer srv.Close()

	r := NewGatewayRouter()
	if err := r.RouteWithConfig(context.Background(), RouteConfig{Provider: ProviderVLLM, BaseURL: srv.URL, ModelName: "test-model"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Execute(context.Background(), ExecContext{Prompt: "hello"}); err == nil {
		t.Fatal("expected model hash error")
	}
}

func TestExecuteOpenAICompatibleProviders(t *testing.T) {
	for _, provider := range []ProviderType{ProviderLlamaCPP, ProviderVLLM, ProviderLMStudio} {
		t.Run(string(provider), func(t *testing.T) {
			srv := newOpenAICompatibleServer(t, "server-version")
			defer srv.Close()

			r := NewGatewayRouter()
			if err := r.RouteWithConfig(context.Background(), RouteConfig{
				Provider:  provider,
				BaseURL:   srv.URL,
				ModelName: "test-model",
				ModelHash: "sha256:def",
			}); err != nil {
				t.Fatal(err)
			}
			res, err := r.Execute(context.Background(), ExecContext{Prompt: "hello"})
			if err != nil {
				t.Fatal(err)
			}
			if res.Content != "ok" || res.ModelHash != "sha256:def" {
				t.Fatalf("unexpected result: %+v", res)
			}
		})
	}
}

func newOpenAICompatibleServer(t *testing.T, version string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": version})
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", version)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "test-model"}}})
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "ok"}}},
		})
	})
	return httptest.NewServer(mux)
}
