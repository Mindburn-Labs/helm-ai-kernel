package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// A one-pixel PNG, inline: its bytes are far fewer than the tokens a provider
// bills for any image.
const gatewayTinyPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="

// TestGatewayRefusesWhatTheQuoteCannotPrice (helm-tracker#313 r1, F2): the
// governed gateway reads a request against the model gateway's closed list for
// its route, so a request that makes the provider bill something the quote
// cannot see (stored state, remote media, hosted tools, an unknown member) is
// refused with 400 naming it, before any quote or dispatch.
func TestGatewayRefusesWhatTheQuoteCannotPrice(t *testing.T) {
	for name, test := range map[string]struct{ path, body, member string }{
		"chat: a remote image":          {"/v1/chat/completions", `{"model":"gpt-6-sol","max_tokens":16,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.test/huge.png","detail":"high"}}]}]}`, "image_url"},
		"chat: web_search_options":      {"/v1/chat/completions", `{"model":"gpt-6-sol","max_tokens":16,"web_search_options":{"search_context_size":"high"},"messages":[{"role":"user","content":"news"}]}`, "web_search_options"},
		"chat: a repeated n":            {"/v1/chat/completions", `{"model":"gpt-6-sol","max_tokens":16,"n":5,"n":1,"messages":[{"role":"user","content":"x"}]}`, "repeats the key"},
		"chat: Models":                  {"/v1/chat/completions", `{"model":"gpt-6-sol","max_tokens":16,"Models":["x"],"messages":[{"role":"user","content":"x"}]}`, "Models"},
		"chat: a reasoning budget":      {"/v1/chat/completions", `{"model":"gpt-6-sol","max_tokens":16,"reasoning":{"max_tokens":100000},"messages":[{"role":"user","content":"x"}]}`, "reasoning"},
		"chat: transforms":              {"/v1/chat/completions", `{"model":"gpt-6-sol","max_tokens":16,"transforms":["middle-out"],"messages":[{"role":"user","content":"x"}]}`, "transforms"},
		"chat: a priority tier":         {"/v1/chat/completions", `{"model":"gpt-6-sol","max_tokens":16,"service_tier":"priority","messages":[{"role":"user","content":"x"}]}`, "service_tier"},
		"chat: an auto tier":            {"/v1/chat/completions", `{"model":"gpt-6-sol","max_tokens":16,"service_tier":"auto","messages":[{"role":"user","content":"x"}]}`, "service_tier"},
		"responses: previous id":        {"/v1/responses", `{"model":"gpt-6-sol","max_output_tokens":16,"previous_response_id":"resp_123","input":"go on"}`, "previous_response_id"},
		"responses: a conversation":     {"/v1/responses", `{"model":"gpt-6-sol","max_output_tokens":16,"conversation":"conv_1","input":"go on"}`, "conversation"},
		"responses: a stored prompt":    {"/v1/responses", `{"model":"gpt-6-sol","max_output_tokens":16,"prompt":{"id":"pmpt_1"}}`, "prompt"},
		"responses: web search":         {"/v1/responses", `{"model":"gpt-6-sol","max_output_tokens":16,"tools":[{"type":"web_search"}],"input":"news"}`, "web_search"},
		"responses: file search":        {"/v1/responses", `{"model":"gpt-6-sol","max_output_tokens":16,"tools":[{"type":"file_search","vector_store_ids":["vs_1"]}],"input":"q"}`, "file_search"},
		"responses: background":         {"/v1/responses", `{"model":"gpt-6-sol","max_output_tokens":16,"background":true,"input":"q"}`, "background"},
		"responses: stored reasoning":   {"/v1/responses", `{"model":"gpt-6-sol","max_output_tokens":16,"input":[{"role":"user","content":"go"},{"type":"reasoning","id":"rs_stored","summary":[]}]}`, "encrypted_content"},
		"embeddings: an unknown member": {"/v1/embeddings", `{"model":"gpt-6-sol","input":"x","future":1}`, "future"},
		"embeddings: an image input":    {"/v1/embeddings", `{"model":"gpt-6-sol","input":[{"type":"image_url","image_url":"https://example.test/a.png"}]}`, "input"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
			rec := f.doBody(t, test.path, []byte(test.body), helmHeaders("idem-closed", "gpt-6-sol"))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), test.member) {
				t.Errorf("status %d (%s), want 400 naming %s", rec.Code, rec.Body.String(), test.member)
			}
			if f.dispatch.called != 0 || f.ledger.HoldCents() != 0 {
				t.Errorf("dispatched %d times, hold %d: the request reached the provider", f.dispatch.called, f.ledger.HoldCents())
			}
		})
	}
}

// TestGatewayHoldsOneTokenPerByteAndTheFloors (F2): the governed gateway's hold
// counts each byte of the request it forwards as an input token, plus the
// floor of each inline image and of each tool definition the provider adds,
// so the hold bounds what the provider can bill for the request.
func TestGatewayHoldsOneTokenPerByteAndTheFloors(t *testing.T) {
	for name, test := range map[string]struct {
		path, body string
		floor      int64
	}{
		"chat: dense text": {"/v1/chat/completions",
			`{"model":"gpt-6-sol","max_tokens":16,"messages":[{"role":"user","content":"` + strings.Repeat("7,", 400) + `"}]}`, 0},
		"chat: an inline image": {"/v1/chat/completions",
			`{"model":"gpt-6-sol","max_tokens":16,"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,` + gatewayTinyPNG + `","detail":"high"}}]}]}`, 2833 + 8*5667},
		"responses: local_shell": {"/v1/responses",
			`{"model":"gpt-6-sol","max_output_tokens":16,"store":false,"input":"ls","tools":[{"type":"local_shell"}]}`, 2000},
		"embeddings: text": {"/v1/embeddings", `{"model":"gpt-6-sol","input":["` + strings.Repeat("a b ", 200) + `"]}`, 0},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
			rec := f.doBody(t, test.path, []byte(test.body), helmHeaders("idem-bound", "gpt-6-sol"))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			quote := decodeHELM(t, rec).Quote
			want := int64(len(f.dispatch.body)) + test.floor
			if quote == nil || quote.InputTokens < want {
				t.Fatalf("held %+v input tokens; the forwarded request is %d bytes with a %d-token floor", quote, len(f.dispatch.body), test.floor)
			}
		})
	}
}

// TestGatewayResponsesAreNotStored (F3): a Responses request that names no
// store is forwarded with store false, so nothing it produces can be billed
// again by reference.
func TestGatewayResponsesAreNotStored(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	rec := f.doBody(t, "/v1/responses", []byte(`{"model":"gpt-6-sol","max_output_tokens":16,"input":"hi"}`), helmHeaders("idem-store", "gpt-6-sol"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(f.dispatch.body, &sent); err != nil || string(sent["store"]) != "false" {
		t.Fatalf("forwarded store = %s (%v), want false: %s", sent["store"], err, f.dispatch.body)
	}
}

// TestGatewayBillAboveTheHoldClosesTheEnvelope (F2): a provider bill above the
// hold is debited as billed, but its usage receipt does not claim the envelope
// covered it, and the envelope takes no further dispatch in its period.
func TestGatewayBillAboveTheHoldClosesTheEnvelope(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapDebitActual, 50)
	rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders("idem-over", "gpt-6-sol"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	meta := decodeHELM(t, rec)
	if meta.OverageCents <= 0 || meta.ActualAmountCents != 55 {
		t.Fatalf("meta = %+v, want the 55-cent bill debited above the hold", meta)
	}
	if meta.UsageReceiptView == nil || meta.UsageReceiptView.ReasonCode == string(economic.SpendReasonOKWithinEnvelope) {
		t.Errorf("the usage receipt of a bill above the hold says %+v", meta.UsageReceiptView)
	}
	if meta.ReasonCode == economic.SpendReasonOKWithinEnvelope {
		t.Errorf("the response reports %s for a bill the envelope did not cover", meta.ReasonCode)
	}
	next := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders("idem-after", "gpt-6-sol"))
	if next.Code != http.StatusForbidden || f.dispatch.called != 1 {
		t.Fatalf("after a bill above the hold the envelope answered %d and dispatched %d times: %s", next.Code, f.dispatch.called, next.Body.String())
	}
}
