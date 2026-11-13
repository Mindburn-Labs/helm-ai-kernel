package spendproxy

import (
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"
)

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
