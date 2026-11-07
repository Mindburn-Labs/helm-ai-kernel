package gateway

import (
	"context"
	"testing"
)

// RouteWithConfig is the live binding path (`helm-ai-kernel local`): it
// refuses an unknown or missing provider or model, fills the provider's
// default endpoint, and normalizes the base URL.
func TestRouteWithConfigBindsAndValidates(t *testing.T) {
	ctx := context.Background()
	r := NewGatewayRouter()

	for name, cfg := range map[string]RouteConfig{
		"missing provider": {ModelName: "m"},
		"unknown provider": {Provider: "nonesuch", ModelName: "m"},
		"missing model":    {Provider: ProviderOllama},
		"invalid base URL": {Provider: ProviderOllama, ModelName: "m", BaseURL: "not a url"},
	} {
		if err := r.RouteWithConfig(ctx, cfg); err == nil {
			t.Errorf("%s: RouteWithConfig accepted %+v", name, cfg)
		}
	}
	if r.ActiveProfile() != nil {
		t.Fatal("a refused config must not bind a profile")
	}

	for provider, want := range map[ProviderType]string{
		ProviderOllama:   "http://localhost:11434",
		ProviderLlamaCPP: "http://localhost:8080",
		ProviderVLLM:     "http://localhost:8000",
		ProviderLMStudio: "http://localhost:1234",
	} {
		if err := r.RouteWithConfig(ctx, RouteConfig{Provider: provider, ModelName: "m"}); err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		p := r.ActiveProfile()
		if p.BaseURL != want || p.ID != "local/"+string(provider) {
			t.Fatalf("%s: bound %+v, want base %s", provider, p, want)
		}
		if p.Capabilities.SupportsTools == (provider == ProviderLlamaCPP) {
			t.Fatalf("%s: tool support = %v", provider, p.Capabilities.SupportsTools)
		}
	}

	if err := r.RouteWithConfig(ctx, RouteConfig{Provider: ProviderVLLM, ModelName: "m", BaseURL: "http://gpu-box:9000/", ProfileID: "lab"}); err != nil {
		t.Fatal(err)
	}
	if p := r.ActiveProfile(); p.BaseURL != "http://gpu-box:9000" || p.ID != "lab" {
		t.Fatalf("explicit endpoint not normalized: %+v", p)
	}
	if defaultBaseURL("nonesuch") != "" {
		t.Fatal("an unknown provider has no default endpoint")
	}
}
