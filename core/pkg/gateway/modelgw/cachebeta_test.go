package modelgw

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// unpricedCacheRoutes is a routes file whose routes name no cache price, as
// the documented example route does.
func unpricedCacheRoutes(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	cfg, err := ParseConfig([]byte(`{"version": 1,
  "providers": [
    {"id": "anthropic", "kind": "anthropic", "base_url": "https://a.test", "key_file": "` + dir + `/a"},
    {"id": "openai", "kind": "openai", "base_url": "https://o.test/v1", "key_file": "` + dir + `/o"},
    {"id": "openrouter", "kind": "openai-compatible", "base_url": "https://r.test/v1", "key_file": "` + dir + `/r"}
  ],
  "routes": [
    {"id": "anthropic/claude-sonnet-5-5", "provider": "anthropic", "model": "claude-sonnet-5-5", "apis": ["anthropic-messages"],
     "price": {"unit": "usd_micros_per_million_tokens", "input": 3000000, "output": 15000000},
     "default_max_output_tokens": 4096, "max_output_tokens": 8192},
    {"id": "openai/gpt-6-sol", "provider": "openai", "model": "gpt-6-sol", "apis": ["openai-chat"],
     "price": {"unit": "usd_micros_per_million_tokens", "input": 2000000, "output": 8000000},
     "default_max_output_tokens": 4096, "max_output_tokens": 8192},
    {"id": "openrouter/anthropic/claude-sonnet-5-5", "provider": "openrouter", "model": "anthropic/claude-sonnet-5-5", "apis": ["openai-chat"],
     "price": {"unit": "usd_micros_per_million_tokens", "input": 3000000, "output": 15000000},
     "default_max_output_tokens": 4096, "max_output_tokens": 8192}
  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestCacheWritesAreHeldAtTheWritePrice (helm-tracker#313 r2, finding 6): on
// an anthropic or openai-compatible route that names no cache-write price, a
// write is priced at Anthropic's published premium, 1.25 times input for 5
// minutes and 2 times for an hour, so the hold of a cache-writing request
// covers a write of every byte, and the settled cost records it. OpenAI bills
// no write premium, so its writes stay at the input price.
func TestCacheWritesAreHeldAtTheWritePrice(t *testing.T) {
	cfg := unpricedCacheRoutes(t)
	for _, test := range []struct {
		route            string
		write5m, write1h int64
	}{
		{"anthropic/claude-sonnet-5-5", 3_750_000, 6_000_000},
		{"openrouter/anthropic/claude-sonnet-5-5", 3_750_000, 6_000_000},
		{"openai/gpt-6-sol", 2_000_000, 2_000_000},
	} {
		var route *Route
		for _, r := range cfg.Routes() {
			if r.ID == test.route {
				route = r
			}
		}
		const tokens = 1_000_000
		cost5m, err := route.Cost(Usage{CacheWrite5mTokens: tokens})
		must(t, err)
		cost1h, err := route.Cost(Usage{CacheWrite1hTokens: tokens})
		must(t, err)
		held, err := route.Quote(tokens, 0, true)
		must(t, err)
		if cost5m != test.write5m || cost1h != test.write1h || held < cost1h {
			t.Errorf("%s: a million written tokens cost %d (5m) and %d (1h), held %d; want %d and %d, held at least the 1h cost",
				test.route, cost5m, cost1h, held, test.write5m, test.write1h)
		}
	}

	// The review's request: 100,000 bytes of a rare character written to the
	// 1-hour cache. At one token per byte the write is billed at 2x input.
	text := strings.Repeat("\U00020000", 25_000)
	body := `{"model":"claude-sonnet-5-5","max_tokens":1,"system":[{"type":"text","text":"` + text + `","cache_control":{"type":"ephemeral","ttl":"1h"}}],"messages":[{"role":"user","content":"go"}]}`
	c, refusal := inspect(cfg, effectargs.APIAnthropicMessages, []byte(body))
	if refusal != nil {
		t.Fatal(refusal.Message)
	}
	held, err := c.Route.Quote(c.inputBound(c.Body), c.MaxOutputTokens, c.MayWriteCache)
	must(t, err)
	billed := 2*3_000_000*c.inputBound(c.Body)/1_000_000 + 15
	if held < billed {
		t.Fatalf("held %d usd_micros for a 1-hour write Anthropic bills at about %d", held, billed)
	}
}

// TestAnthropicBetaIsNotForwardedOffTheMessagesAPI (finding 12): anthropic-beta
// selects Anthropic features, some billed at a premium; it is checked only on
// the Messages API, so it is not forwarded on the OpenAI APIs.
func TestAnthropicBetaIsNotForwardedOffTheMessagesAPI(t *testing.T) {
	cfg := testConfig(t, "https://a.test", "https://o.test/v1", "https://r.test/v1")
	in := http.Header{}
	in.Set("Anthropic-Beta", "context-1m-2025-08-07")
	for _, test := range []struct {
		api, provider string
		forwarded     bool
	}{
		{effectargs.APIOpenAIChat, "openrouter", false},
		{effectargs.APIOpenAIResponses, "openai", false},
		{effectargs.APIAnthropicMessages, "anthropic", true},
	} {
		p := cfg.Provider(test.provider)
		req, _, err := newProviderRequest(context.Background(), p, &call{API: test.api, Body: []byte(`{}`)}, "k", in, "")
		must(t, err)
		if got := req.Header.Get("Anthropic-Beta") != ""; got != test.forwarded {
			t.Errorf("%s: anthropic-beta forwarded = %v, want %v", test.api, got, test.forwarded)
		}
	}
}

// TestPartMembersAreClosedOnTheModelGateway (finding 8): the model gateway
// refuses a member of a part, an item or a block the closed list does not
// name.
func TestPartMembersAreClosedOnTheModelGateway(t *testing.T) {
	refusedNaming(t, map[string]struct{ api, body, member string }{
		"responses: input_text with file_id": {effectargs.APIOpenAIResponses,
			`{"model":"gpt-6-sol","max_output_tokens":16,"input":[{"role":"user","content":[{"type":"input_text","text":"x","file_id":"file-1"}]}]}`, "file_id"},
		"responses: instructions as items": {effectargs.APIOpenAIResponses,
			`{"model":"gpt-6-sol","max_output_tokens":16,"instructions":[{"role":"developer","content":"x"}],"input":"x"}`, "instructions"},
		"chat: a part's file": {effectargs.APIOpenAIChat,
			`{"model":"gpt-6-sol","max_tokens":16,"messages":[{"role":"user","content":[{"type":"text","text":"x","file":{"file_id":"file-1"}}]}]}`, "file"},
		"messages: a block's file_id": {effectargs.APIAnthropicMessages,
			`{"model":"claude-sonnet-5-5","max_tokens":16,"messages":[{"role":"user","content":[{"type":"text","text":"x","file_id":"f"}]}]}`, "file_id"},
	})
}
