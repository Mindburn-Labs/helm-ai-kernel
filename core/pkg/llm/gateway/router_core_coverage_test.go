package gateway

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestBlessedProfileRoutingAndDefaults(t *testing.T) {
	profiles := GetBlessedProfiles()
	if len(profiles) != 4 {
		t.Fatalf("expected 4 blessed profiles, got %d", len(profiles))
	}

	router := NewGatewayRouter()
	if err := router.Route(context.Background(), "local/ollama"); err != nil {
		t.Fatal(err)
	}
	if router.ActiveProfile().Provider != ProviderOllama {
		t.Fatalf("unexpected active profile: %+v", router.ActiveProfile())
	}
	if err := router.Route(context.Background(), "missing-profile"); err == nil {
		t.Fatal("expected unknown blessed profile to fail")
	}

	mismatch := &EnginePinMismatchError{Field: "model", Got: "a", Want: "b"}
	if mismatch.SafeDepHazardCode() != contracts.HazardEnginePinMismatch {
		t.Fatalf("unexpected hazard code: %s", mismatch.SafeDepHazardCode())
	}

	for _, tc := range []struct {
		provider ProviderType
		baseURL  string
		tools    bool
	}{
		{ProviderOllama, "http://localhost:11434", true},
		{ProviderLlamaCPP, "http://localhost:8080", false},
		{ProviderVLLM, "http://localhost:8000", true},
		{ProviderLMStudio, "http://localhost:1234", true},
	} {
		t.Run(string(tc.provider), func(t *testing.T) {
			r := NewGatewayRouter()
			if err := r.RouteWithConfig(context.Background(), RouteConfig{Provider: tc.provider, ModelName: "model"}); err != nil {
				t.Fatal(err)
			}
			if r.ActiveProfile().BaseURL != tc.baseURL {
				t.Fatalf("default base URL = %s, want %s", r.ActiveProfile().BaseURL, tc.baseURL)
			}
			if r.ActiveProfile().Capabilities.SupportsTools != tc.tools {
				t.Fatalf("supports tools = %v, want %v", r.ActiveProfile().Capabilities.SupportsTools, tc.tools)
			}
		})
	}

	for _, cfg := range []RouteConfig{
		{ModelName: "model"},
		{Provider: ProviderOllama},
		{Provider: ProviderOllama, BaseURL: "not-a-url", ModelName: "model"},
	} {
		if err := NewGatewayRouter().RouteWithConfig(context.Background(), cfg); err == nil {
			t.Fatalf("expected invalid route config to fail: %+v", cfg)
		}
	}
}

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

func TestExecuteRejectsCapabilityAndInactiveRouter(t *testing.T) {
	if _, err := NewGatewayRouter().Execute(context.Background(), ExecContext{Prompt: "hello"}); err == nil {
		t.Fatal("expected inactive router execution to fail")
	}

	router := NewGatewayRouter()
	router.activeProfile = &Profile{ID: "no-json", Capabilities: Capabilities{SupportsJSONMode: false}}
	if _, err := router.Execute(context.Background(), ExecContext{Prompt: "hello", JSONMode: true}); err == nil {
		t.Fatal("expected JSON mode capability violation")
	}

	router.activeProfile = &Profile{ID: "no-tools", Capabilities: Capabilities{SupportsJSONMode: true, SupportsTools: false}}
	if _, err := router.Execute(context.Background(), ExecContext{Prompt: "hello", Tools: []string{"tool"}}); err == nil {
		t.Fatal("expected tools capability violation")
	}
}

func TestValidateEnginePinMismatchBranches(t *testing.T) {
	profile := Profile{
		Provider:            ProviderVLLM,
		BaseURL:             "http://localhost:8000",
		ModelName:           "model-a",
		VerifierProfileID:   "verifier-a",
		AttestedMeasurement: "measurement-a",
		AlternateProfileID:  "alternate-a",
	}

	for _, tc := range []struct {
		name string
		pin  *EnginePin
	}{
		{name: "provider", pin: &EnginePin{Provider: ProviderOllama}},
		{name: "base url invalid", pin: &EnginePin{BaseURL: "not-a-url"}},
		{name: "base url mismatch", pin: &EnginePin{BaseURL: "http://localhost:9000"}},
		{name: "model", pin: &EnginePin{ModelName: "model-b"}},
		{name: "model hash", pin: &EnginePin{ModelHash: "sha256:want"}},
		{name: "runtime version", pin: &EnginePin{RuntimeVersion: "runtime-b"}},
		{name: "verifier", pin: &EnginePin{VerifierProfileID: "verifier-b"}},
		{name: "measurement", pin: &EnginePin{AttestedMeasurement: "measurement-b"}},
		{name: "alternate", pin: &EnginePin{ApprovedAlternateProfileID: "alternate-b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEnginePin(Profile{
				Provider:            profile.Provider,
				BaseURL:             profile.BaseURL,
				ModelName:           profile.ModelName,
				VerifierProfileID:   profile.VerifierProfileID,
				AttestedMeasurement: profile.AttestedMeasurement,
				AlternateProfileID:  profile.AlternateProfileID,
				EnginePin:           tc.pin,
			}, "runtime-a", "sha256:got")
			if err == nil {
				t.Fatal("expected engine pin validation to fail")
			}
		})
	}
}

func TestDiscoveryAndProviderErrorBranches(t *testing.T) {
	router := NewGatewayRouter()
	if hash, err := router.discoverModelHash(context.Background(), Profile{Provider: ProviderVLLM}); err != nil || hash != "" {
		t.Fatalf("non-Ollama hash discovery = %q, err=%v", hash, err)
	}

	tags := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []map[string]string{{"name": "other", "digest": "sha256:other"}}})
	}))
	defer tags.Close()
	if hash, err := router.discoverModelHash(context.Background(), Profile{Provider: ProviderOllama, BaseURL: tags.URL, ModelName: "wanted"}); err != nil || hash != "" {
		t.Fatalf("unexpected unmatched Ollama digest: %q err=%v", hash, err)
	}

	emptyOllama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"message": map[string]string{"content": ""}})
	}))
	defer emptyOllama.Close()
	if _, err := router.executeOllama(context.Background(), Profile{Provider: ProviderOllama, BaseURL: emptyOllama.URL, ModelName: "model"}, ExecContext{Prompt: "hello"}); err == nil {
		t.Fatal("expected empty Ollama content to fail")
	}

	emptyOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{}})
	}))
	defer emptyOpenAI.Close()
	if _, err := router.executeOpenAICompatible(context.Background(), Profile{Provider: ProviderVLLM, BaseURL: emptyOpenAI.URL, ModelName: "model"}, ExecContext{Prompt: "hello"}); err == nil {
		t.Fatal("expected empty OpenAI-compatible content to fail")
	}
}

func TestExecuteOpenAICompatibleSendsJSONModeToolsAndSystem(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "server-version"})
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if _, ok := payload["response_format"].(map[string]any); !ok {
			t.Fatalf("expected JSON response format in payload: %#v", payload)
		}
		if tools, ok := payload["tools"].([]any); !ok || len(tools) != 1 {
			t.Fatalf("expected tools in payload: %#v", payload)
		}
		messages, ok := payload["messages"].([]any)
		if !ok || len(messages) != 2 {
			t.Fatalf("expected system and user messages: %#v", payload)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "json-ok"}}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	router := NewGatewayRouter()
	if err := router.RouteWithConfig(context.Background(), RouteConfig{Provider: ProviderVLLM, BaseURL: srv.URL, ModelName: "model", ModelHash: "sha256:model"}); err != nil {
		t.Fatal(err)
	}
	result, err := router.Execute(context.Background(), ExecContext{
		Prompt: "hello", System: "system", JSONMode: true, Tools: []string{"tool"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Content != "json-ok" {
		t.Fatalf("unexpected content: %+v", result)
	}
}

func TestGatewayHTTPHelpersReportErrors(t *testing.T) {
	router := NewGatewayRouter()
	var out map[string]any
	if err := router.getJSON(context.Background(), "http://[::1", &out); err == nil {
		t.Fatal("expected invalid GET endpoint to fail")
	}
	if err := router.postJSON(context.Background(), "http://example.test", map[string]float64{"bad": math.NaN()}, &out); err == nil {
		t.Fatal("expected unmarshalable POST payload to fail")
	}
	if err := router.postJSON(context.Background(), "http://[::1", map[string]string{"ok": "ok"}, &out); err == nil {
		t.Fatal("expected invalid POST endpoint to fail")
	}

	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "provider failed", http.StatusInternalServerError)
	}))
	defer fail.Close()
	if err := router.getJSON(context.Background(), fail.URL, &out); err == nil || !strings.Contains(err.Error(), "provider failed") {
		t.Fatalf("expected GET HTTP error with body, got %v", err)
	}
	if err := router.postJSON(context.Background(), fail.URL, map[string]string{"ok": "ok"}, &out); err == nil || !strings.Contains(err.Error(), "provider failed") {
		t.Fatalf("expected POST HTTP error with body, got %v", err)
	}
}
