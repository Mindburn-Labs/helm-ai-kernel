package modelgw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigResolvesRoutesByIDAndByProviderModel(t *testing.T) {
	cfg := testConfig(t, "https://api.anthropic.com", "https://api.openai.com/v1", "https://openrouter.ai/api/v1")
	for _, test := range []struct {
		api, model, want string
	}{
		{"anthropic-messages", "claude-sonnet-5-5", routeSonnet},
		{"anthropic-messages", routeSonnet, routeSonnet},
		{"anthropic-messages", "claude-haiku-4-5-20251001", routeHaiku},
		{"anthropic-messages", "claude-opus-5-5", routeOpus},
		{"openai-responses", "gpt-6-sol", routeGPT},
		{"openai-chat", routeGPT, routeGPT},
		{"openai-chat", "deepseek/deepseek-chat", routeOR},
	} {
		r, ok := cfg.Resolve(test.api, test.model)
		if !ok || r.ID != test.want {
			t.Errorf("Resolve(%s, %s) = %v %v, want %s", test.api, test.model, r, ok, test.want)
		}
	}
	// A model is a route only on the APIs it serves: Claude is not on chat, and
	// the OpenAI model is not on Messages ("Claude routes only").
	for _, test := range [][2]string{
		{"openai-chat", "claude-sonnet-5-5"}, {"anthropic-messages", "gpt-6-sol"}, {"openai-responses", "deepseek/deepseek-chat"}, {"openai-chat", "nope"},
	} {
		if r, ok := cfg.Resolve(test[0], test[1]); ok {
			t.Errorf("Resolve(%s, %s) = %s, want none", test[0], test[1], r.ID)
		}
	}
	if got := len(cfg.Routes()); got != 5 || cfg.Routes()[0].ID != routeHaiku {
		t.Fatalf("routes = %d, first %s", got, cfg.Routes()[0].ID)
	}
	if cfg.Provider("anthropic").Auth != AuthXAPIKey || cfg.Provider("openai").Auth != AuthBearer || cfg.Provider("openrouter").Auth != AuthBearer {
		t.Fatal("provider auth defaults follow the kind")
	}
	if cfg.Provider("openai").BaseURL != "https://api.openai.com/v1" {
		t.Fatalf("base url = %s", cfg.Provider("openai").BaseURL)
	}
	// The chat maximum field defaults by kind.
	if r, _ := cfg.Resolve("openai-chat", "gpt-6-sol"); r.ChatMaxTokensField != ChatMaxCompletionTokens {
		t.Fatalf("openai chat field = %s", r.ChatMaxTokensField)
	}
	if r, _ := cfg.Resolve("openai-chat", "deepseek/deepseek-chat"); r.ChatMaxTokensField != ChatMaxTokens {
		t.Fatalf("openai-compatible chat field = %s", r.ChatMaxTokensField)
	}
	if files := cfg.KeyFiles(); len(files) != 3 || !strings.HasSuffix(files["anthropic"], "/anthropic") {
		t.Fatalf("key files = %v", files)
	}
	if cfg.MaxRequestBytes != 1048576 || cfg.ReplayTTL != time.Hour || cfg.CallTimeout != 30*time.Second || cfg.IdleTimeout != time.Second || cfg.MaxReplayBytes != defaultMaxReplayBytes {
		t.Fatalf("limits = %+v", cfg)
	}
}

func TestConfigDefaultsLimits(t *testing.T) {
	cfg, err := ParseConfig([]byte(strings.Replace(routesJSON("https://a.test", "https://o.test/v1", "https://r.test/v1", "/keys"),
		`"limits": {"max_request_bytes": 1048576, "replay_ttl": "1h", "call_timeout": "30s", "idle_timeout": "1s"}`, `"limits": {}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxRequestBytes != defaultMaxRequestBytes || cfg.ReplayTTL != defaultReplayTTL || cfg.CallTimeout != defaultCallTimeout || cfg.IdleTimeout != defaultIdleTimeout {
		t.Fatalf("defaults = %+v", cfg)
	}
}

func TestConfigRefusesWhatItCannotServeSafely(t *testing.T) {
	base := routesJSON("https://api.anthropic.com", "https://api.openai.com/v1", "https://openrouter.ai/api/v1", "/keys")
	edit := func(old, new string) string {
		t.Helper()
		if !strings.Contains(base, old) {
			t.Fatalf("test edit %q is not in the base config", old)
		}
		return strings.Replace(base, old, new, 1)
	}
	for name, test := range map[string]struct{ raw, want string }{
		"an unknown field":            {edit(`"version": 1,`, `"version": 1, "typo": true,`), "unknown field"},
		"trailing data":               {base + `{}`, "trailing data"},
		"another version":             {edit(`"version": 1`, `"version": 2`), "version must be 1"},
		"no providers":                {`{"version": 1, "providers": [], "routes": []}`, "no providers"},
		"a duplicate provider":        {edit(`{"id": "openai", "kind": "openai"`, `{"id": "anthropic", "kind": "openai"`), "defined twice"},
		"an unknown kind":             {edit(`"kind": "openai-compatible"`, `"kind": "azure"`), "kind must be"},
		"plain http off loopback":     {edit(`"https://openrouter.ai/api/v1"`, `"http://openrouter.ai/api/v1"`), "https"},
		"credentials in the url":      {edit(`"https://openrouter.ai/api/v1"`, `"https://user:pw@openrouter.ai/api/v1"`), "credentials"},
		"a query in the url":          {edit(`"https://openrouter.ai/api/v1"`, `"https://openrouter.ai/api/v1?key=1"`), "query"},
		"a relative key file":         {edit(`"key_file": "/keys/openai"`, `"key_file": "keys/openai"`), "absolute"},
		"an unknown provider":         {edit(`"provider": "openai", "model": "gpt-6-sol"`, `"provider": "azure", "model": "gpt-6-sol"`), "unknown provider"},
		"an unknown api":              {edit(`"apis": ["openai-chat"]`, `"apis": ["openai-completions"]`), "not one of"},
		"a kind that cannot serve":    {edit(`"model": "claude-opus-5-5", "apis": ["anthropic-messages"]`, `"model": "claude-opus-5-5", "apis": ["openai-chat"]`), "does not serve"},
		"an unpriced route":           {edit(`"price": {"unit": "usd_micros_per_million_tokens", "input": 42000, "output": 110000}`, `"price": {"unit": "usd_micros_per_million_tokens", "input": 42000}`), "unpriced"},
		"a negative price":            {edit(`"input": 42000`, `"input": -1`), "must be from 0"},
		"another price unit":          {edit(`"unit": "usd_micros_per_million_tokens", "input": 42000`, `"unit": "usd_cents", "input": 42000`), "price.unit"},
		"a default above the maximum": {edit(`"default_max_output_tokens": 4096, "max_output_tokens": 8192`, `"default_max_output_tokens": 9000, "max_output_tokens": 8192`), "default_max_output_tokens"},
		"no maximum":                  {edit(`"default_max_output_tokens": 4096, "max_output_tokens": 8192`, `"default_max_output_tokens": 4096`), "default_max_output_tokens"},
		"a chat field without chat": {edit(`"apis": ["anthropic-messages"],
     "price": {"unit": "usd_micros_per_million_tokens", "input": 5000000`, `"apis": ["anthropic-messages"], "chat_max_tokens_field": "max_tokens",
     "price": {"unit": "usd_micros_per_million_tokens", "input": 5000000`), "openai-chat"},
		"a bad route id":               {edit(`"id": "anthropic/claude-opus-5-5"`, `"id": "anthropic claude"`), "id must be"},
		"a duplicate route":            {edit(`"id": "openai/gpt-6-sol"`, `"id": "anthropic/claude-opus-5-5"`), "defined twice"},
		"an ambiguous model name":      {edit(`"model": "claude-haiku-4-5-20251001"`, `"model": "claude-opus-5-5"`), "names both route"},
		"a request limit out of range": {edit(`"max_request_bytes": 1048576`, `"max_request_bytes": 10`), "max_request_bytes"},
		"a bad duration":               {edit(`"replay_ttl": "1h"`, `"replay_ttl": "soon"`), "replay_ttl"},
		"a duration out of range":      {edit(`"call_timeout": "30s"`, `"call_timeout": "100h"`), "call_timeout"},
	} {
		_, err := ParseConfig([]byte(test.raw))
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: err = %v, want one naming %q", name, err, test.want)
		}
	}
	// Known good control: a loopback http provider.
	good := strings.Replace(base, `"https://openrouter.ai/api/v1"`, `"http://127.0.0.1:9/v1"`, 1)
	if _, err := ParseConfig([]byte(good)); err != nil {
		t.Errorf("a loopback http provider: %v", err)
	}
}

func TestLoadConfigReadsABoundedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(path, []byte(routesJSON("https://a.test", "https://o.test/v1", "https://r.test/v1", dir)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(filepath.Join(dir, "absent.json")); err == nil {
		t.Fatal("a missing routes file loaded")
	}
	huge := filepath.Join(dir, "huge.json")
	if err := os.WriteFile(huge, []byte(`{"version": 1, "x": "`+strings.Repeat("a", maxConfigBytes)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(huge); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("an oversized routes file: %v", err)
	}
}
