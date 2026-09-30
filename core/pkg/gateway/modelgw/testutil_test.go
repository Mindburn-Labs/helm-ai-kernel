package modelgw

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Route ids and provider model ids of the current model line-up, as a
// deployment's routes file names them. The prices are illustrative: a
// deployment sets its own from the providers' tariffs.
const (
	routeOpus   = "anthropic/claude-opus-5-5"
	routeSonnet = "anthropic/claude-sonnet-5-5"
	routeHaiku  = "anthropic/claude-haiku-4-5-20251001"
	routeGPT    = "openai/gpt-6-sol"
	routeOR     = "openrouter/deepseek/deepseek-chat"
)

// routesJSON is a routes file with the four providers pointed at the given base
// URLs (anthropic, openai, openrouter) and key files under dir.
func routesJSON(anthropic, openai, openrouter, dir string) string {
	return fmt.Sprintf(`{
  "version": 1,
  "providers": [
    {"id": "anthropic", "kind": "anthropic", "base_url": %q, "key_file": %q},
    {"id": "openai", "kind": "openai", "base_url": %q, "key_file": %q},
    {"id": "openrouter", "kind": "openai-compatible", "base_url": %q, "key_file": %q}
  ],
  "routes": [
    {"id": %q, "provider": "anthropic", "model": "claude-opus-5-5", "apis": ["anthropic-messages"],
     "price": {"unit": "usd_micros_per_million_tokens", "input": 5000000, "output": 25000000, "cache_read": 500000, "cache_write_5m": 6250000, "cache_write_1h": 10000000},
     "default_max_output_tokens": 8192, "max_output_tokens": 64000},
    {"id": %q, "provider": "anthropic", "model": "claude-sonnet-5-5", "apis": ["anthropic-messages"],
     "price": {"unit": "usd_micros_per_million_tokens", "input": 3000000, "output": 15000000, "cache_read": 300000, "cache_write_5m": 3750000, "cache_write_1h": 6000000},
     "default_max_output_tokens": 8192, "max_output_tokens": 64000},
    {"id": %q, "provider": "anthropic", "model": "claude-haiku-4-5-20251001", "apis": ["anthropic-messages"],
     "price": {"unit": "usd_micros_per_million_tokens", "input": 1000000, "output": 5000000, "cache_read": 100000, "cache_write_5m": 1250000, "cache_write_1h": 2000000},
     "default_max_output_tokens": 4096, "max_output_tokens": 32000},
    {"id": %q, "provider": "openai", "model": "gpt-6-sol", "apis": ["openai-responses", "openai-chat"],
     "price": {"unit": "usd_micros_per_million_tokens", "input": 2000000, "output": 8000000, "cache_read": 500000},
     "default_max_output_tokens": 8192, "max_output_tokens": 32000},
    {"id": %q, "provider": "openrouter", "model": "deepseek/deepseek-chat", "apis": ["openai-chat"],
     "price": {"unit": "usd_micros_per_million_tokens", "input": 42000, "output": 110000},
     "default_max_output_tokens": 4096, "max_output_tokens": 8192}
  ],
  "limits": {"max_request_bytes": 1048576, "replay_ttl": "1h", "call_timeout": "30s", "idle_timeout": "1s"}
}`, anthropic, filepath.Join(dir, "anthropic"), openai, filepath.Join(dir, "openai"), openrouter, filepath.Join(dir, "openrouter"),
		routeOpus, routeSonnet, routeHaiku, routeGPT, routeOR)
}

// testConfig parses routesJSON.
func testConfig(t testing.TB, anthropic, openai, openrouter string) *Config {
	t.Helper()
	cfg, err := ParseConfig([]byte(routesJSON(anthropic, openai, openrouter, t.TempDir())))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// keyFiles writes one key file per provider, named for the provider, and
// returns the directory.
func keyFiles(t testing.TB, keys map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for provider, key := range keys {
		if err := os.WriteFile(filepath.Join(dir, provider), []byte(key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
