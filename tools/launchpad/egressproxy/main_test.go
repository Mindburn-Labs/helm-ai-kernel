package main

import "testing"

func TestNetworkAllowedNormalizesOpenRouterURLAllowlist(t *testing.T) {
	allowlist := []string{"https://openrouter.ai/api/v1", "https://api.openrouter.ai/api/v1"}

	if !networkAllowed("openrouter.ai:443", allowlist) {
		t.Fatal("expected openrouter.ai CONNECT destination to match URL allowlist")
	}
	if !networkAllowed("api.openrouter.ai:443", allowlist) {
		t.Fatal("expected api.openrouter.ai CONNECT destination to match URL allowlist")
	}
	if networkAllowed("example.com:443", allowlist) {
		t.Fatal("expected non-OpenRouter destination to remain denied")
	}
}
