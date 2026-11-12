package spendproxy

import (
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

const legacyBody = `{"model":"base-model","max_tokens":4000,"messages":[{"role":"user","content":"hi"}]}`

// TestALegacyJournalDoesNotCloseAnEnvelopeOnRestart (helm-tracker#313 r4
// review, N1): before holds included the platform fee, a journal line's
// quote ceiling excluded it, so an ordinary bill debited above it. A restart
// on such a log must not read that as a bill above the hold and close the
// envelope for the day.
func TestALegacyJournalDoesNotCloseAnEnvelopeOnRestart(t *testing.T) {
	var calls atomic.Int64
	f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		replyWithUsage("", 20, 1000)(w, r)
	})
	if status, body := f.postRaw(t, "/v1/chat/completions", legacyBody, "legacy-1"); status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	debit := f.held()
	if debit < 2 {
		t.Fatalf("the request debited %d cents, want at least 2", debit)
	}
	records := f.records(t)
	rewritten := 0
	for _, rec := range records {
		if isDispatchJournal(rec) {
			// A journal written by the released proxy: no note, and a ceiling
			// below what the bill debited once the fee was added.
			rec.Note = ""
			rec.RouteQuote.MaxAmountCents = debit - 1
			rec.RouteQuote.QuotedAmountCents = min(rec.RouteQuote.QuotedAmountCents, debit-1)
			rewritten++
		}
	}
	if rewritten != 1 {
		t.Fatalf("rewrote %d journal lines, want 1", rewritten)
	}
	f.writeLog(t, records)
	f.restart(t)
	before := calls.Load()
	if status, body := f.postRaw(t, "/v1/chat/completions", legacyBody, "legacy-2"); status != http.StatusOK || calls.Load() != before+1 {
		t.Fatalf("after a restart on a legacy log the envelope refused an ordinary request: status %d (%s), %d dispatches", status, body, calls.Load()-before)
	}
}

// TestASettlementLineClosesOnlyItsOwnEnvelope (r4 review, N4): the closure
// members of a settlement line sit outside its signed payload, so a line that
// names another envelope must not close that envelope on restart.
func TestASettlementLineClosesOnlyItsOwnEnvelope(t *testing.T) {
	f := newProxyFixture(t)
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "scope-1", nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	sub := f.server.envelopes["env-sub"]
	today := inferencegateway.PeriodWindow(sub.Period, time.Now().UTC())
	records := f.records(t)
	edited := 0
	for _, rec := range records {
		if rec.Kind == RecordSettlement {
			rec.EnvelopeClosed, rec.EnvelopeClosedWindows = "env-sub", []string{today}
			edited++
		}
	}
	if edited != 1 {
		t.Fatalf("edited %d settlement lines, want 1", edited)
	}
	f.writeLog(t, records)
	f.restart(t)
	next := f.post(t, "/v1/chat/completions", "mini-model", "env-sub", "scope-sub", nil)
	_, _ = io.Copy(io.Discard, next.Body)
	_ = next.Body.Close()
	if next.StatusCode != http.StatusOK {
		t.Fatalf("an edited settlement line of env-direct closed env-sub: next request status %d", next.StatusCode)
	}
}
