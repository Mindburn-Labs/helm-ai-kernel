package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayHealthCheckBranches(t *testing.T) {
	if err := NewGatewayRouter().HealthCheck(context.Background()); err == nil {
		t.Fatal("expected health check without route to fail")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": ""})
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "model"}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	router := NewGatewayRouter()
	if err := router.RouteWithConfig(context.Background(), RouteConfig{Provider: ProviderVLLM, BaseURL: srv.URL, ModelName: "model", ModelHash: "sha256:model"}); err != nil {
		t.Fatal(err)
	}
	if err := router.HealthCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	version, err := router.runtimeVersion(context.Background(), *router.ActiveProfile())
	if err != nil {
		t.Fatal(err)
	}
	if version != "openai-compatible" {
		t.Fatalf("expected fallback runtime version, got %q", version)
	}

	badHealth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer badHealth.Close()
	if _, err := router.openAICompatibleHealth(context.Background(), Profile{Provider: ProviderLlamaCPP, BaseURL: badHealth.URL}); err == nil {
		t.Fatal("expected non-2xx OpenAI-compatible health to fail")
	}
	if _, err := router.runtimeVersion(context.Background(), Profile{Provider: ProviderType("custom"), BaseURL: srv.URL}); err == nil {
		t.Fatal("expected unsupported provider runtime version to fail")
	}
}
