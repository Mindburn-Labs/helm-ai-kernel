package spendproxy

import (
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A released idempotency key may dispatch again. The second attempt carries
// a fresh signed quote, although its intent and quote IDs are unchanged.
func releasedThenPending(t *testing.T) (*proxyFixture, []*ReceiptRecord) {
	t.Helper()
	f := newProxyFixture(t)
	first, _ := journalOnly(settledOnce(t, f, "attempt-retry", nil))
	f.writeLog(t, first)
	_ = f.server.Close()
	opts := f.reconcileOptions(t, first[0].SpendIntentID)
	opts.Release, opts.Reason = true, "provider confirms first attempt was not billed"
	if _, err := Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	prior := f.records(t)
	if len(prior) != 2 || prior[1].Kind != RecordDispatchReleased {
		t.Fatalf("expected first journal and signed release, got %v", prior)
	}
	records := settledOnce(t, f, "attempt-retry", nil)
	second, _ := journalOnly(records[len(prior):])
	if len(second) != 1 {
		t.Fatal("released key did not dispatch again")
	}
	a, b := first[0].RouteQuote, second[0].RouteQuote
	if a.ID != b.ID || a.SpendIntentID != b.SpendIntentID || a.ReceiptHash == b.ReceiptHash {
		t.Fatal("retry must reuse intent and quote IDs with a new signed receipt hash")
	}
	kept := append(prior, second[0])
	_ = f.server.Close()
	f.writeLog(t, kept)
	return f, kept
}

func TestAReleasedAttemptCannotReleaseItsRetry(t *testing.T) {
	for _, replay := range []string{"release", "journal and release", "journal", "duplicate current journal"} {
		t.Run(replay, func(t *testing.T) {
			f, records := releasedThenPending(t)
			switch replay {
			case "release":
				f.appendLine(t, records[1])
			case "journal and release":
				f.appendLine(t, records[0])
				f.appendLine(t, records[1])
			case "journal":
				f.appendLine(t, records[0])
			case "duplicate current journal":
				f.appendLine(t, records[2])
			}
			f.start(t)
			pending := f.server.pending
			if len(pending) != 1 || pending[0].Quote.ReceiptHash != records[2].RouteQuote.ReceiptHash || f.held() != records[2].RouteQuote.MaxAmountCents {
				t.Fatalf("replay changed the current pending attempt: %+v, hold %d", pending, f.held())
			}
			resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "attempt-retry", nil)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK || f.upstream.calls.Load() != 2 {
				t.Fatalf("pending retry dispatched: status %d, calls %d", resp.StatusCode, f.upstream.calls.Load())
			}
			// A genuine release of the current attempt still frees its hold;
			// replaying that release is harmless and the key can dispatch again.
			_ = f.server.Close()
			opts := f.reconcileOptions(t, records[2].SpendIntentID)
			opts.Release, opts.Reason = true, "provider confirms retry was not billed"
			if _, err := Reconcile(opts); err != nil {
				t.Fatal(err)
			}
			all := f.records(t)
			f.appendLine(t, all[len(all)-1])
			f.start(t)
			if f.held() != 0 || f.server.ReplaySummary().PendingDispatches != 0 {
				t.Fatal("current release did not free its own hold")
			}
			settledOnce(t, f, "attempt-retry", nil)
			if f.upstream.calls.Load() != 3 {
				t.Fatal("genuinely released retry did not permit one new dispatch")
			}
		})
	}
}

func TestReleaseMustMatchTheActiveSignedAttempt(t *testing.T) {
	for _, field := range []string{"quote ID", "content hash", "receipt hash", "created at", "expires at"} {
		t.Run(field, func(t *testing.T) {
			f, _, _ := pendingFixture(t)
			release := releaseRecord(f.server.pending[0].Quote, "a different attempt")
			q := release.RouteQuote
			switch field {
			case "quote ID":
				q.ID += "-another"
			case "content hash":
				q.MaxAmountCents++
			case "receipt hash":
				q.ReceiptHash = strings.ReplaceAll(q.ReceiptHash, "a", "b") + "0"
			case "created at":
				q.CreatedAt = q.CreatedAt.Add(time.Nanosecond)
			case "expires at":
				q.ExpiresAt = q.ExpiresAt.Add(time.Nanosecond)
			}
			q.Reseal()
			if err := f.server.signRecord(release); err != nil {
				t.Fatal(err)
			}
			_ = f.server.Close()
			f.appendLine(t, release)
			if err := f.tryStart(t); err == nil || !strings.Contains(err.Error(), "active dispatch attempt") {
				t.Fatalf("restart accepted a release for a different %s: %v", field, err)
			}
		})
	}
}

func TestRecoveryRefusesOverlappingDispatchAttempts(t *testing.T) {
	f, records := releasedThenPending(t)
	f.writeLog(t, []*ReceiptRecord{records[0], records[2]})
	if err := f.tryStart(t); err == nil || !strings.Contains(err.Error(), "unreleased dispatch attempt") {
		t.Fatalf("restart silently replaced an unreleased attempt: %v", err)
	}
}

func TestAReleaseCannotBorrowAnotherSignedRecord(t *testing.T) {
	for _, edit := range []string{"journal kind", "target intent", "tenant", "unversioned action", "unknown action"} {
		t.Run(edit, func(t *testing.T) {
			f := newProxyFixture(t)
			settledOnce(t, f, "release-first", nil)
			records := settledOnce(t, f, "release-second", nil)
			var journals []*ReceiptRecord
			for _, rec := range records {
				if isDispatchJournal(rec) {
					journals = append(journals, rec)
				}
			}
			if len(journals) != 2 {
				t.Fatalf("got %d journals, want two distinct dispatches", len(journals))
			}
			f.writeLog(t, journals)
			f.restart(t)
			release := releaseRecord(journals[0].RouteQuote, "provider confirms no dispatch")
			if err := f.server.signRecord(release); err != nil {
				t.Fatal(err)
			}
			switch edit {
			case "journal kind":
				copy := *journals[0]
				release = &copy
				release.Kind = RecordDispatchReleased
			case "target intent":
				release.SpendIntentID = journals[1].SpendIntentID
			case "tenant":
				release.TenantID = "another-tenant"
			case "unversioned action", "unknown action":
				delete(release.RouteQuote.Metadata, "release_action")
				if edit == "unknown action" {
					release.RouteQuote.Metadata["release_action"] = "dispatch_released/v999"
				}
				if err := f.server.signRecord(release); err != nil {
					t.Fatal(err)
				}
			}
			pub, err := ParsePublicKey(f.server.SigningPublicKey())
			if err != nil {
				t.Fatal(err)
			}
			// The payload's original signature remains valid in every attack.
			if err := verifyDetached(pub, release.Payload(), release.PayloadSignature); err != nil {
				t.Fatalf("fixture changed the signed bytes: %v", err)
			}
			_ = f.server.Close()
			f.appendLine(t, release)
			if err := f.tryStart(t); err == nil {
				t.Error("restart applied a release whose action or identity was not signed")
			}
			if _, _, err := verifyIntentSignatures(map[string]ed25519.PublicKey{release.PayloadSignatureKeyID: pub}, release.SpendIntentID, []*ReceiptRecord{release}, nil); err == nil {
				t.Error("export verified the relabeled or redirected release")
			}
		})
	}
}

func TestFailedSettlementRestoresTheRecordedLiability(t *testing.T) {
	f, calls, _ := settleFailedOverage(t)
	if got := f.server.ledger.AvailableCents(); got != 0 {
		t.Fatalf("live failed settlement left %d cents available despite its known liability", got)
	}
	for _, phase := range []string{"live", "restarted"} {
		if phase == "restarted" {
			f.restart(t)
			if got := f.server.ReplaySummary().PendingCents; got != 5001 {
				t.Fatalf("restart held %d cents for a recorded 5001-cent bill", got)
			}
		}
		if got := f.server.ledger.AvailableCents(); got != 0 {
			t.Fatalf("%s: unfunded liability left %d cents available", phase, got)
		}
		resp := f.post(t, "/v1/chat/completions", "base-model", "env-sub", "other-envelope-"+phase, nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || calls.Load() != 1 {
			t.Fatalf("%s: other envelope status %d, provider calls %d; want no new dispatch", phase, resp.StatusCode, calls.Load())
		}
	}
}

func TestReconciliationKeepsAnUnfundedRecoveryHold(t *testing.T) {
	f, _ := overageSettled(t)
	var kept []*ReceiptRecord
	var intent string
	for _, rec := range f.records(t) {
		if rec.Kind != RecordSettlement {
			kept = append(kept, rec)
		}
		if rec.Kind == RecordUsage {
			intent = rec.SpendIntentID
		}
	}
	f.writeLog(t, kept)
	_ = f.server.Close()
	f.raiseOpening(t, "2000", "6")
	opts := f.reconcileOptions(t, intent)
	opts.SettleCents, opts.Reason = 11, "provider confirms the recorded bill"
	if _, err := Reconcile(opts); err == nil || !strings.Contains(err.Error(), "available funds") {
		t.Fatalf("settlement of an unfunded recovered hold: %v; want insufficient funds", err)
	}
	f.start(t)
	if got := f.server.ReplaySummary(); got.PendingCents != 11 || got.DebitedCents != 0 || f.server.BalanceCents() != 6 {
		t.Fatalf("failed reconciliation changed the books: %+v, balance %d", got, f.server.BalanceCents())
	}
	_ = f.server.Close()
	f.raiseOpening(t, "6", "2000")
	opts = f.reconcileOptions(t, intent)
	opts.SettleCents, opts.Reason = 11, "provider confirms the recorded bill; funds restored"
	if res, err := Reconcile(opts); err != nil || res.DebitedCents != 11 {
		t.Fatalf("funded reconciliation: %+v, %v", res, err)
	}
	f.start(t)
	if got := f.server.ReplaySummary(); got.PendingDispatches != 0 || got.DebitedCents != 11 {
		t.Fatalf("funded reconciliation did not settle exactly once: %+v", got)
	}
}
