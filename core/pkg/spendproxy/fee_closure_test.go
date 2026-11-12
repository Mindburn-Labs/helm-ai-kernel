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
)

// honouringMax answers like a provider that honours the forwarded output
// maximum and generates all of it: the prompt tokens given, and completion
// tokens equal to the forwarded max_tokens.
func honouringMax(prompt int64, calls *atomic.Int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Model     string `json:"model"`
			MaxTokens int64  `json:"max_tokens"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"cmpl-h","object":"chat.completion","model":%q,"choices":[],"usage":{"prompt_tokens":%d,"completion_tokens":%d}}`, req.Model, prompt, req.MaxTokens)
	}
}

// TestAPlatformFeeIsInsideTheProxysHold (helm-tracker#313 r2, finding 1): with
// a platform fee, a provider that honours the output maximum bills within the
// hold, so the debit is within it, the receipt does not blame the provider,
// and the envelope stays open.
func TestAPlatformFeeIsInsideTheProxysHold(t *testing.T) {
	cfg := strings.Replace(testConfigJSON, `"platform_fee_bps": 0,`, `"platform_fee_bps": 1000,`, 1)
	var calls atomic.Int64
	f := newProxyFixtureWithUpstream(t, cfg, honouringMax(10, &calls))
	status, body := f.postRaw(t, "/v1/chat/completions", `{"model":"base-model","max_tokens":4000,"messages":[{"role":"user","content":"write a long story"}]}`, "fee-1")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var hold int64
	var usage *economic.UsageReceipt
	for _, rec := range f.records(t) {
		if rec.Kind == RecordRouteQuote && rec.Note == NoteDispatchJournal {
			hold = rec.RouteQuote.MaxAmountCents
		}
		if rec.Kind == RecordUsage {
			usage = rec.Usage
		}
	}
	if usage == nil || usage.ActualAmountCents > hold {
		t.Errorf("debited %d cents against a hold of %d", usage.ActualAmountCents, hold)
	}
	if usage.BudgetVerdict == economic.BudgetVerdictEscalate || usage.Metadata["envelope_closed"] != "" {
		t.Errorf("a provider bill within the hold (%d cents of %d) is reported as %s/%s, metadata %v",
			usage.ProviderCostCents, hold, usage.BudgetVerdict, usage.ReasonCode, usage.Metadata)
	}
	status, body = f.postRaw(t, "/v1/chat/completions", `{"model":"base-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`, "fee-2")
	if status != http.StatusOK || calls.Load() != 2 {
		t.Errorf("the next request: status %d, %d dispatches: %s", status, calls.Load(), body)
	}
}

// overageConfig is the test config whose balance cannot cover a bill far
// above the hold, so its settlement fails after the provider was paid.
func overageConfig() string {
	return strings.Replace(testConfigJSON, `"opening_cents": 2000`, `"opening_cents": 60`, 1)
}

// settleFailedOverage runs one request whose provider bills 5001 cents
// against a 1-cent hold and a 60-cent balance: the settlement fails.
func settleFailedOverage(t *testing.T) (*proxyFixture, *atomic.Int64, string) {
	t.Helper()
	var calls atomic.Int64
	f := newProxyFixtureWithUpstream(t, overageConfig(), func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		replyWithUsage("", 1_000_000, 16)(w, r)
	})
	status, body := f.postRaw(t, "/v1/chat/completions", `{"model":"base-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`, "sf-1")
	if status != http.StatusInternalServerError || !strings.Contains(body, string(economic.SpendReasonSettlementMissing)) {
		t.Fatalf("status %d: %s; want the settlement to fail", status, body)
	}
	var intent string
	for _, rec := range f.records(t) {
		if rec.Kind == RecordSettleFailed {
			intent = rec.SpendIntentID
		}
	}
	if intent == "" {
		t.Fatal("no settle_failed line")
	}
	return f, &calls, intent
}

// TestAnOverageWhoseSettlementFailsStaysClosed (finding 3): a bill above the
// hold whose settlement fails closes the envelope, the settle_failed line
// records the overage and the closure, signed, and a restart replays it.
func TestAnOverageWhoseSettlementFailsStaysClosed(t *testing.T) {
	f, calls, _ := settleFailedOverage(t)
	for _, phase := range []string{"live", "after a restart"} {
		if phase == "after a restart" {
			f.restart(t)
		}
		status, body := f.postRaw(t, "/v1/chat/completions", `{"model":"base-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`, "sf-next-"+strings.ReplaceAll(phase, " ", "-"))
		if status != http.StatusForbidden || !strings.Contains(body, string(economic.SpendReasonEnvelopeInactive)) || calls.Load() != 1 {
			t.Errorf("%s: status %d, %d dispatches (%s); want 403 %s and no dispatch", phase, status, calls.Load(), body, economic.SpendReasonEnvelopeInactive)
		}
	}
	for _, rec := range f.records(t) {
		if rec.Kind != RecordSettleFailed {
			continue
		}
		meta := rec.RouteQuote.Metadata
		if meta["envelope_closed"] != "env-direct" || meta["overage_cents"] != "5000" || meta["actual_amount_cents"] != "5001" || meta["envelope_closed_windows"] == "" {
			t.Errorf("the settle_failed line's route quote metadata is %v; want the overage and the closure", meta)
		}
		pub, _ := ParsePublicKey(f.server.SigningPublicKey())
		if err := verifyDetached(pub, rec.Payload(), rec.PayloadSignature); err != nil {
			t.Errorf("the settle_failed line is not signed over what it says: %v", err)
		}
	}
}

// TestRestartClosesTheWindowsTheReceiptNames (finding 2): a restart closes the
// windows a usage receipt names, whatever time its line was written at.
func TestRestartClosesTheWindowsTheReceiptNames(t *testing.T) {
	var calls atomic.Int64
	f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		replyWithUsage("", 48_189, 16)(w, r)
	})
	if status, body := f.postRaw(t, "/v1/chat/completions", `{"model":"mini-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`, "rw-over"); status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	// The line was written a day earlier than its settlement's window: a
	// restart must close the window the receipt names, not the line's day.
	records := f.records(t)
	for _, rec := range records {
		if rec.Kind == RecordUsage || rec.Kind == RecordSettlement {
			rec.RecordedAt = rec.RecordedAt.Add(-24 * time.Hour)
		}
	}
	f.writeLog(t, records)
	f.restart(t)
	status, body := f.postRaw(t, "/v1/chat/completions", `{"model":"mini-model","max_tokens":16,"messages":[{"role":"user","content":"again"}]}`, "rw-next")
	if status != http.StatusForbidden || calls.Load() != 1 {
		t.Fatalf("after a restart: status %d, %d dispatches (%s); want the closed window refused", status, calls.Load(), body)
	}
}

// TestRestartBooksTheRecordedWindow (finding 2): a restart books a settled
// debit in the window its usage receipt names, so a spent envelope stays spent
// whatever time its lines were written at.
func TestRestartBooksTheRecordedWindow(t *testing.T) {
	f := newProxyFixtureWithConfig(t, twoCentConfig())
	for i := range 2 {
		if resp := f.post(t, "/v1/chat/completions", "mini-model", "env-direct", fmt.Sprintf("idem-booked-%d", i), nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}
	records := f.records(t)
	for _, rec := range records {
		if rec.Kind == RecordUsage || rec.Kind == RecordSettlement {
			rec.RecordedAt = rec.RecordedAt.Add(-24 * time.Hour)
		}
	}
	f.writeLog(t, records)
	f.restart(t)
	if resp := f.post(t, "/v1/chat/completions", "mini-model", "env-direct", "idem-booked-after", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("after a restart a spent 2-cent envelope answered %d", resp.StatusCode)
	}
}
