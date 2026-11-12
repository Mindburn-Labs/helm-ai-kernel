package spendproxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// refusedUnforwarded checks that each body gets 400 naming its member and
// never reaches the provider.
func refusedUnforwarded(t *testing.T, cases map[string]struct{ path, body, member string }) {
	t.Helper()
	for name, form := range cases {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				replyWithUsage("", 10, 1)(w, r)
			})
			status, body := f.postRaw(t, form.path, form.body, "idem-r3")
			if status != http.StatusBadRequest || !strings.Contains(body, form.member) {
				t.Errorf("status %d (%s), want 400 naming %s", status, body, form.member)
			}
			if calls.Load() != 0 || f.held() != 0 {
				t.Errorf("forwarded %d times, holding %d cents", calls.Load(), f.held())
			}
		})
	}
}

// TestSpendProxyRefusesCacheWrites (helm-tracker#313 r2, finding 6): the
// proxy's price book has no cache-write price and it reads no cache usage, so
// a request that asks the provider to write a prompt cache is refused, in any
// spelling of the key.
func TestSpendProxyRefusesCacheWrites(t *testing.T) {
	refusedUnforwarded(t, map[string]struct{ path, body, member string }{
		"a 1h write on a text part": {"/v1/chat/completions", `{"model":"base-model","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"xxxxxxxxxx","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]}`, "cache_control"},
		"an escaped key":            {"/v1/chat/completions", `{"model":"base-model","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"x","cache_control":{"type":"ephemeral"}}]}]}`, "cache_control"},
		"on an image part":          {"/v1/chat/completions", `{"model":"base-model","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AA=="},"cache_control":{"type":"ephemeral"}}]}]}`, "cache_control"},
	})
}

// TestSpendProxyRefusesUnknownPartMembers (finding 8): the members of a part
// and an item are closed, and Responses instructions is a string.
func TestSpendProxyRefusesUnknownPartMembers(t *testing.T) {
	refusedUnforwarded(t, map[string]struct{ path, body, member string }{
		"responses: a part's file_id":         {"/v1/responses", `{"model":"base-model","max_output_tokens":1,"input":[{"role":"user","content":[{"type":"input_text","text":"x","file_id":"file-1"}]}]}`, "file_id"},
		"chat: a part's file":                 {"/v1/chat/completions", `{"model":"base-model","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"x","file":{"file_id":"file-1"}}]}]}`, "file"},
		"responses: instructions as items":    {"/v1/responses", `{"model":"base-model","max_output_tokens":1,"instructions":[{"role":"developer","content":[{"type":"input_image","image_url":"https://x.test/a.png"}]}],"input":"x"}`, "instructions"},
		"responses: an item's unknown member": {"/v1/responses", `{"model":"base-model","max_output_tokens":1,"input":[{"type":"function_call_output","call_id":"c1","output":"ok","attachments":["file-1"]}]}`, "attachments"},
	})
}

// TestAVersionSuffixIsPricedAtTheDearerAnsweredPrice (mutant N28): an answer
// that names the quoted id with a suffix that is not a date is debited at the
// answered model's price when it is dearer and the price book has it.
func TestAVersionSuffixIsPricedAtTheDearerAnsweredPrice(t *testing.T) {
	cfg := strings.Replace(testConfigJSON, `{"provider_id": "mockai", "model_id": "mini-model", "input_token_micro_cents": 1000, "output_token_micro_cents": 2000}`,
		`{"provider_id": "mockai", "model_id": "mini-model", "input_token_micro_cents": 1000, "output_token_micro_cents": 2000},
    {"provider_id": "mockai", "model_id": "mini-model-pro", "input_token_micro_cents": 5000, "output_token_micro_cents": 10000}`, 1)
	if cfg == testConfigJSON {
		t.Fatal("the price entry was not added")
	}
	f := newProxyFixtureWithUpstream(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"c","model":"mini-model-pro","choices":[],"usage":{"prompt_tokens":100,"completion_tokens":100}}`)
	})
	status, body := f.postRaw(t, "/v1/chat/completions", `{"model":"mini-model","max_tokens":4000,"messages":[{"role":"user","content":"hi"}]}`, "idem-suffix")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	for _, rec := range f.records(t) {
		if rec.Kind != RecordUsage {
			continue
		}
		// 100 x 1000 + 100 x 2000 micro-cents is 1 cent at the quoted price;
		// at mini-model-pro's 100 x 5000 + 100 x 10000 it is 2.
		if rec.Usage.BalanceDebitCents != 2 || rec.Usage.Metadata["model_mismatch"] != MismatchVersion {
			t.Fatalf("debited %d cents, metadata %v; want 2 at the dearer answered price", rec.Usage.BalanceDebitCents, rec.Usage.Metadata)
		}
		return
	}
	t.Fatal("no usage line")
}
