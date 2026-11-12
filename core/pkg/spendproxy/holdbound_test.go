package spendproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// postRaw sends body as is, with the governance headers of env-direct.
func (f *proxyFixture) postRaw(t *testing.T, path, body, idem string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.http.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(inferencegateway.HeaderAgent, "agent-live")
	req.Header.Set(inferencegateway.HeaderSpendEnvelope, "env-direct")
	req.Header.Set(inferencegateway.HeaderIdempotencyKey, idem)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// replyWithUsage answers like a provider that reports the given usage.
func replyWithUsage(model string, prompt, completion int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		answered := model
		if answered == "" {
			answered = requestModel(r)
		} else {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"cmpl-u","object":"chat.completion","model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":%d,"completion_tokens":%d}}`, answered, prompt, completion)
	}
}

// TestSpendProxyRefusesWhatTheQuoteCannotPrice (helm-tracker#313 r1, F2): the
// spend proxy reads a request against the model gateway's closed list, so the
// forms its byte-count quote cannot see never reach the provider.
func TestSpendProxyRefusesWhatTheQuoteCannotPrice(t *testing.T) {
	for name, form := range map[string]struct{ path, body, member string }{
		"chat: a remote image":                 {"/v1/chat/completions", `{"model":"base-model","max_tokens":16,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.test/huge.png","detail":"high"}}]}]}`, "image_url"},
		"chat: web_search_options":             {"/v1/chat/completions", `{"model":"base-model","max_tokens":16,"web_search_options":{"search_context_size":"high"},"messages":[{"role":"user","content":"news"}]}`, "web_search_options"},
		"chat: a repeated n":                   {"/v1/chat/completions", `{"model":"base-model","max_tokens":16,"n":5,"n":1,"messages":[{"role":"user","content":"x"}]}`, `n`},
		"chat: Models":                         {"/v1/chat/completions", `{"model":"base-model","max_tokens":16,"Models":["x"],"messages":[{"role":"user","content":"x"}]}`, "Models"},
		"chat: an OpenRouter reasoning budget": {"/v1/chat/completions", `{"model":"base-model","max_tokens":16,"reasoning":{"max_tokens":100000},"messages":[{"role":"user","content":"x"}]}`, "reasoning"},
		"chat: OpenRouter transforms":          {"/v1/chat/completions", `{"model":"base-model","max_tokens":16,"transforms":["middle-out"],"messages":[{"role":"user","content":"x"}]}`, "transforms"},
		"responses: previous_response_id":      {"/v1/responses", `{"model":"base-model","max_output_tokens":16,"previous_response_id":"resp_123","input":"go on"}`, "previous_response_id"},
		"responses: a conversation":            {"/v1/responses", `{"model":"base-model","max_output_tokens":16,"conversation":"conv_1","input":"go on"}`, "conversation"},
		"responses: a stored prompt":           {"/v1/responses", `{"model":"base-model","max_output_tokens":16,"prompt":{"id":"pmpt_1"}}`, "prompt"},
		"responses: hosted web search":         {"/v1/responses", `{"model":"base-model","max_output_tokens":16,"tools":[{"type":"web_search"}],"input":"news"}`, "web_search"},
		"responses: file search":               {"/v1/responses", `{"model":"base-model","max_output_tokens":16,"tools":[{"type":"file_search","vector_store_ids":["vs_1"]}],"input":"q"}`, "file_search"},
		"responses: background":                {"/v1/responses", `{"model":"base-model","max_output_tokens":16,"background":true,"input":"q"}`, "background"},
		"responses: stored reasoning by id":    {"/v1/responses", `{"model":"base-model","max_output_tokens":16,"input":[{"role":"user","content":"go"},{"type":"reasoning","id":"rs_stored","summary":[]}]}`, "encrypted_content"},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				replyWithUsage("", 10, 1)(w, r)
			})
			status, body := f.postRaw(t, form.path, form.body, "idem-closed")
			if status != http.StatusBadRequest || !strings.Contains(body, form.member) {
				t.Errorf("status %d (%s), want 400 naming %s", status, body, form.member)
			}
			if calls.Load() != 0 || f.held() != 0 {
				t.Errorf("forwarded %d times, holding %d cents", calls.Load(), f.held())
			}
		})
	}
}

// TestABillAboveTheHoldClosesTheEnvelope (F2): a provider that bills above the
// hold anyway is debited what it billed, the usage receipt says the envelope
// did not cover it, an alert is logged, and the envelope takes no further
// dispatch in its period, also after a restart.
func TestABillAboveTheHoldClosesTheEnvelope(t *testing.T) {
	var calls atomic.Int64
	f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// 48,189 input tokens, far above what a short text request can carry.
		replyWithUsage("", 48_189, 16)(w, r)
	})
	status, body := f.postRaw(t, "/v1/chat/completions", `{"model":"mini-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`, "idem-over")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var hold, debited int64
	var usage *economic.UsageReceipt
	for _, rec := range f.records(t) {
		if rec.Kind == RecordRouteQuote && rec.RouteQuote != nil {
			hold = rec.RouteQuote.MaxAmountCents
		}
		if rec.Kind == RecordUsage {
			usage = rec.Usage
			debited = rec.Usage.BalanceDebitCents
		}
	}
	if debited != 49 || debited <= hold {
		t.Fatalf("debited %d cents against a hold of %d, want the 49 cents billed", debited, hold)
	}
	if usage.ReasonCode == economic.SpendReasonOKWithinEnvelope || usage.Metadata["envelope_closed"] == "" {
		t.Errorf("the usage receipt of a bill above the hold says %s/%s, metadata %v", usage.BudgetVerdict, usage.ReasonCode, usage.Metadata)
	}
	if len(f.alerts()) == 0 {
		t.Error("no alert for a bill above the hold")
	}
	for _, phase := range []string{"after the bill", "after a restart"} {
		if phase == "after a restart" {
			f.restart(t)
		}
		status, body := f.postRaw(t, "/v1/chat/completions", `{"model":"mini-model","max_tokens":16,"messages":[{"role":"user","content":"again"}]}`, "idem-next-"+strings.ReplaceAll(phase, " ", "-"))
		if status != http.StatusForbidden || !strings.Contains(body, string(economic.SpendReasonEnvelopeInactive)) || calls.Load() != 1 {
			t.Fatalf("%s: status %d, %d dispatches (%s), want 403 %s and no dispatch", phase, status, calls.Load(), body, economic.SpendReasonEnvelopeInactive)
		}
	}
}

// TestSpendProxyResponsesAreNotStored (F3): a Responses request reaches the
// provider with store false.
func TestSpendProxyResponsesAreNotStored(t *testing.T) {
	f := newProxyFixture(t)
	status, body := f.postRaw(t, "/v1/responses", `{"model":"base-model","max_output_tokens":16,"input":"hi"}`, "idem-store")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	raw, _ := f.upstream.lastBody.Load().([]byte)
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(raw, &sent); err != nil || string(sent["store"]) != "false" {
		t.Fatalf("forwarded store = %s (%v): %s", sent["store"], err, raw)
	}
}

// TestAnswerModelRule (F8, mutants M29 and M30): the quoted model's answer is
// priced at its usage; an answer that names no model, or the quoted id with a
// suffix that is not a date, is priced at its usage too and the difference is
// recorded; a model the price book does not know is debited at least the hold.
func TestAnswerModelRule(t *testing.T) {
	for name, test := range map[string]struct {
		answered     string
		wantAtLeast  bool // debited at least the hold
		wantMismatch bool
	}{
		"the quoted model":              {"base-model", false, false},
		"an 8-digit dated snapshot":     {"base-model-20250514", false, false},
		"a dashed dated snapshot":       {"base-model-2025-05-14", false, false},
		"no model":                      {"", false, true},
		"a version suffix":              {"base-model-v3-0324", false, true},
		"a model the book cannot price": {"gpt-9-ultra", true, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				model := ""
				if test.answered != "" {
					model = fmt.Sprintf(`"model":%q,`, test.answered)
				}
				_, _ = fmt.Fprintf(w, `{"id":"c",%s"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5}}`, model)
			})
			status, body := f.postRaw(t, "/v1/chat/completions", `{"model":"base-model","max_tokens":4000,"messages":[{"role":"user","content":"hi"}]}`, "idem-answer")
			if status != http.StatusOK {
				t.Fatalf("status %d: %s", status, body)
			}
			var hold, debited int64
			var notes map[string]string
			for _, rec := range f.records(t) {
				if rec.Kind == RecordRouteQuote && rec.RouteQuote != nil {
					hold = rec.RouteQuote.MaxAmountCents
				}
				if rec.Kind == RecordUsage {
					debited, notes = rec.Usage.BalanceDebitCents, rec.Usage.Metadata
				}
			}
			// 10 x 5000 + 5 x 10000 micro-cents: 1 cent at base-model's price.
			switch {
			case test.wantAtLeast && debited < hold:
				t.Errorf("debited %d cents, want at least the %d-cent hold", debited, hold)
			case !test.wantAtLeast && debited != 1:
				t.Errorf("debited %d cents (hold %d), want the 1-cent usage", debited, hold)
			}
			if got := notes["model_mismatch"] != ""; got != test.wantMismatch {
				t.Errorf("model_mismatch recorded = %v (%v), want %v", got, notes, test.wantMismatch)
			}
		})
	}
}

// TestClientThatLeavesDoesNotCancelTheProviderCall (mutant M33): the provider
// call outlives the client, so it settles on what the provider reports instead
// of being cut and debited at its hold.
func TestClientThatLeavesDoesNotCancelTheProviderCall(t *testing.T) {
	var canceled atomic.Bool
	done := make(chan struct{})
	f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		model := requestModel(r)
		select {
		case <-time.After(300 * time.Millisecond):
		case <-r.Context().Done():
			canceled.Store(true)
			return
		}
		providerReply(w, model, 1)
	})
	req, _ := http.NewRequest(http.MethodPost, f.http.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"base-model","max_tokens":4000,"messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set(inferencegateway.HeaderAgent, "agent-live")
	req.Header.Set(inferencegateway.HeaderSpendEnvelope, "env-direct")
	req.Header.Set(inferencegateway.HeaderIdempotencyKey, "idem-leaves")
	if resp, err := (&http.Client{Timeout: 50 * time.Millisecond}).Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("the client was meant to give up first")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the provider call never ended")
	}
	deadline := time.Now().Add(3 * time.Second)
	for f.server.ledger.HoldCents() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if canceled.Load() {
		t.Fatal("the client's departure cancelled the provider call")
	}
	// 100 x 5000 + 20 x 10000 micro-cents: 1 cent, far below the hold.
	if debited := 2000 - f.server.BalanceCents(); debited != 1 {
		t.Fatalf("debited %d cents, want the 1 cent the provider reported", debited)
	}
}
