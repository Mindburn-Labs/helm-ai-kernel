package modelgw

import "testing"

// TestTheFiveMinuteWriteDefaultRoundsUp (helm-tracker#313 r3, mutant R45): a
// route that names no 5-minute cache-write price writes at 1.25 times its
// input price rounded up, so the default never prices a write below the
// premium: an input price of 3 writes at 4.
func TestTheFiveMinuteWriteDefaultRoundsUp(t *testing.T) {
	dir := t.TempDir()
	cfg, err := ParseConfig([]byte(`{"version": 1,
  "providers": [{"id": "anthropic", "kind": "anthropic", "base_url": "https://a.test", "key_file": "` + dir + `/a"}],
  "routes": [
    {"id": "anthropic/odd-price", "provider": "anthropic", "model": "odd-price", "apis": ["anthropic-messages"],
     "price": {"unit": "usd_micros_per_million_tokens", "input": 3, "output": 15},
     "default_max_output_tokens": 16, "max_output_tokens": 16}
  ]}`))
	must(t, err)
	route := cfg.Routes()[0]
	cost, err := route.Cost(Usage{CacheWrite5mTokens: 1_000_000})
	must(t, err)
	if cost != 4 {
		t.Fatalf("a million tokens written for 5 minutes at an input price of 3 cost %d usd_micros, want 4 (3 x 1.25 rounded up)", cost)
	}
}
