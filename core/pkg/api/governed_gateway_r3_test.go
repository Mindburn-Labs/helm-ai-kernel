package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// TestGatewayReplayReportsTheUsageReceiptsVerdict (helm-tracker#313 r2,
// finding 11): an identical replay of a settled overage reports the verdict
// its usage receipt carries, not ALLOW.
func TestGatewayReplayReportsTheUsageReceiptsVerdict(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapDebitActual, 50)
	first := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders("idem-replay-over", "gpt-6-sol"))
	if first.Code != http.StatusOK {
		t.Fatalf("status %d: %s", first.Code, first.Body.String())
	}
	if meta := decodeHELM(t, first); meta.Verdict != economic.BudgetVerdictEscalate {
		t.Fatalf("the overage reports %s, want ESCALATE", meta.Verdict)
	}
	replay := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders("idem-replay-over", "gpt-6-sol"))
	if replay.Code != http.StatusOK || f.dispatch.called != 1 {
		t.Fatalf("replay: status %d, %d dispatches: %s", replay.Code, f.dispatch.called, replay.Body.String())
	}
	meta := decodeHELM(t, replay)
	if !meta.Replayed || meta.Verdict != economic.BudgetVerdictEscalate || replay.Header().Get("X-HELM-Verdict") != string(economic.BudgetVerdictEscalate) {
		t.Fatalf("the replay reports %s (header %s) with %s; want the usage receipt's ESCALATE", meta.Verdict, replay.Header().Get("X-HELM-Verdict"), meta.ReasonCode)
	}
}

// TestGatewayRefusesCacheWrites (finding 6): the governed gateway prices no
// cache write, so a request that asks for one is refused before any quote.
func TestGatewayRefusesCacheWrites(t *testing.T) {
	for name, body := range map[string]string{
		"a text part":    `{"model":"gpt-6-sol","max_tokens":16,"messages":[{"role":"user","content":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]}`,
		"an escaped key": `{"model":"gpt-6-sol","max_tokens":16,"messages":[{"role":"user","content":[{"type":"text","text":"x","cache_control":{"type":"ephemeral"}}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
			rec := f.doBody(t, "/v1/chat/completions", []byte(body), helmHeaders("idem-cache", "gpt-6-sol"))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "cache_control") || f.dispatch.called != 0 {
				t.Fatalf("status %d (%s), %d dispatches; want 400 naming cache_control", rec.Code, rec.Body.String(), f.dispatch.called)
			}
		})
	}
}

// TestGatewayHoldIncludesThePlatformFee (finding 1): the governed gateway's
// hold is the provider quote with the platform fee on it, and a provider bill
// at its quote settles inside it.
func TestGatewayHoldIncludesThePlatformFee(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapDebitActual, 1)
	rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders("idem-fee-probe", "gpt-6-sol"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	quote := decodeHELM(t, rec).Quote
	// The fixture's fee is 1000 bps: the hold is the quote plus ceil(10%).
	if want := quote.QuotedAmountCents + (quote.QuotedAmountCents*1000+9_999)/10_000; quote.MaxAmountCents != want {
		t.Fatalf("hold %d for a %d-cent quote, want %d with the fee", quote.MaxAmountCents, quote.QuotedAmountCents, want)
	}
	f.dispatch.cost = quote.QuotedAmountCents
	next := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders("idem-fee", "gpt-6-sol"))
	meta := decodeHELM(t, next)
	if next.Code != http.StatusOK || meta.OverageCents != 0 || meta.Verdict != economic.BudgetVerdictAllow || meta.ActualAmountCents > meta.Quote.MaxAmountCents {
		t.Fatalf("a bill at its quote: status %d, verdict %s, actual %d, overage %d, hold %d", next.Code, meta.Verdict, meta.ActualAmountCents, meta.OverageCents, meta.Quote.MaxAmountCents)
	}
}
