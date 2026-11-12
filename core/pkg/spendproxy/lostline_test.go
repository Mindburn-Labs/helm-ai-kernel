package spendproxy

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

const lostLineBody = `{"model":"base-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`

// overageSettled runs one request whose provider bills 11 cents against a
// 1-cent hold, within the balance: the settlement commits and closes the
// envelope for the day.
func overageSettled(t *testing.T) (*proxyFixture, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	f := newProxyFixtureWithUpstream(t, testConfigJSON, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		replyWithUsage("", 2_000, 16)(w, r)
	})
	if status, body := f.postRaw(t, "/v1/chat/completions", lostLineBody, "lost-1"); status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	if f.held() != 11 {
		t.Fatalf("the overage debited %d cents, want 11", f.held())
	}
	return f, &calls
}

// envelopeClosed reports whether the next request is refused because the
// envelope is closed, and that it reached no provider.
func envelopeClosed(t *testing.T, f *proxyFixture, calls *atomic.Int64, idem string) bool {
	t.Helper()
	before := calls.Load()
	status, body := f.postRaw(t, "/v1/chat/completions", lostLineBody, idem)
	return status == http.StatusForbidden && strings.Contains(body, string(economic.SpendReasonEnvelopeInactive)) && calls.Load() == before
}

// lostLineAfterOverage drops the lost line of an overage that closed the
// envelope and restarts the proxy: the envelope stays closed, the dispatch is
// held at the debit the log records, the log's record of the bill guards
// reconcile, and a reconciled settlement is debited once.
func lostLineAfterOverage(t *testing.T, lost RecordKind) {
	f, calls := overageSettled(t)
	if !envelopeClosed(t, f, calls, "lost-live") {
		t.Fatal("the overage did not close the envelope")
	}
	var kept []*ReceiptRecord
	intent := ""
	for _, rec := range f.records(t) {
		if rec.Kind == lost {
			intent = rec.SpendIntentID
			continue
		}
		kept = append(kept, rec)
	}
	f.writeLog(t, kept)
	f.restart(t)
	if !envelopeClosed(t, f, calls, "lost-restarted") {
		t.Errorf("after a restart without the %s line the envelope took a request (%d dispatches)", lost, calls.Load())
	}
	if rs := f.server.ReplaySummary(); rs.PendingDispatches != 1 || rs.PendingCents != 11 || f.held() != 11 {
		t.Errorf("after a restart without the %s line: pending %d holding %d, %d cents kept; want 1 holding the 11 cents the log records", lost, rs.PendingDispatches, rs.PendingCents, f.held())
	}

	_ = f.server.Close()
	f.http.Close()
	opts := f.reconcileOptions(t, intent)
	opts.Release, opts.Reason = true, "the provider shows nothing"
	if _, err := Reconcile(opts); err == nil {
		t.Errorf("a dispatch whose %s line was lost was released", lost)
	}
	opts.Release, opts.SettleCents, opts.Reason = false, 1, "one cent"
	if _, err := Reconcile(opts); err == nil {
		t.Errorf("a dispatch whose %s line was lost settled below the 11 cents the log records", lost)
	}
	opts.SettleCents, opts.Reason = 11, "the provider console shows 11 cents"
	if res, err := Reconcile(opts); err != nil || res.DebitedCents != 11 {
		t.Fatalf("reconcile at the recorded actual: %+v, %v", res, err)
	}
	f.start(t)
	if rs := f.server.ReplaySummary(); rs.PendingDispatches != 0 || f.held() != 11 {
		t.Errorf("after reconcile and a restart: pending %d, %d cents kept; want the 11 cents debited once", rs.PendingDispatches, f.held())
	}
	if !envelopeClosed(t, f, calls, "lost-reconciled") {
		t.Errorf("after reconcile and a restart the envelope took a request")
	}
}

// TestAnOverageWhoseSettlementLineIsLostStaysClosed (helm-tracker#313 r3,
// finding 1; the review's TestR3_SP_LostSettlementAfterOverage): the usage
// line of a bill above the hold names the windows it closed; a restart closes
// them though its settlement line never reached the log.
func TestAnOverageWhoseSettlementLineIsLostStaysClosed(t *testing.T) {
	lostLineAfterOverage(t, RecordSettlement)
}

// TestAnOverageWhoseUsageLineIsLostStaysClosed (finding 1; the review's
// TestR3_SP_LostUsageAfterOverage): the settlement line of a bill above the
// hold closes the envelope on restart though its usage line was lost.
func TestAnOverageWhoseUsageLineIsLostStaysClosed(t *testing.T) {
	lostLineAfterOverage(t, RecordUsage)
}

// TestRestartClosesALegacyClosureInTheWindowOfItsLine (mutant R48): a usage
// receipt written before the windows were recorded names the envelope it
// closed and no window; a restart closes the window of its line's time, here
// a later day than the one its dispatch was journalled in.
func TestRestartClosesALegacyClosureInTheWindowOfItsLine(t *testing.T) {
	f, calls := overageSettled(t)
	records := f.records(t)
	for _, rec := range records {
		switch rec.Kind {
		case RecordRouteQuote, RecordBudgetVerdict:
			rec.RecordedAt = rec.RecordedAt.Add(-72 * time.Hour)
		case RecordUsage:
			delete(rec.Usage.Metadata, inferencegateway.MetadataEnvelopeWindow)
			delete(rec.Usage.Metadata, inferencegateway.MetadataEnvelopeClosedWindows)
			if err := f.server.signRecord(rec); err != nil {
				t.Fatal(err)
			}
		case RecordSettlement:
			rec.EnvelopeClosed, rec.EnvelopeClosedWindows = "", nil
		}
	}
	f.writeLog(t, records)
	f.restart(t)
	if !envelopeClosed(t, f, calls, "legacy-next") {
		t.Fatalf("after a restart a legacy closure left the envelope open today (%d dispatches)", calls.Load())
	}
}

// TestASettlementLineNamesTheWindowsItsUsageClosed (finding 1): the settlement
// line of a bill above the hold names the windows its usage receipt closed,
// so a restart that finds it without its usage line closes them, though its
// dispatch was journalled in another window.
func TestASettlementLineNamesTheWindowsItsUsageClosed(t *testing.T) {
	f, calls := overageSettled(t)
	var kept []*ReceiptRecord
	for _, rec := range f.records(t) {
		switch rec.Kind {
		case RecordUsage:
			continue
		case RecordRouteQuote, RecordBudgetVerdict:
			rec.RecordedAt = rec.RecordedAt.Add(-72 * time.Hour)
		case RecordSettlement:
			if rec.EnvelopeClosed != "env-direct" || len(rec.EnvelopeClosedWindows) == 0 {
				t.Errorf("the settlement line names envelope %q windows %v; want the windows its usage receipt closed", rec.EnvelopeClosed, rec.EnvelopeClosedWindows)
			}
		}
		kept = append(kept, rec)
	}
	f.writeLog(t, kept)
	f.restart(t)
	if !envelopeClosed(t, f, calls, "named-next") {
		t.Fatalf("after a restart without the usage line the window its settlement line names is open (%d dispatches)", calls.Load())
	}
}
