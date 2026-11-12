package spendproxy

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// pendingFixture leaves one dispatch pending: a settled run whose log is cut
// back to its journal line, as if the process stopped mid-call.
func pendingFixture(t *testing.T) (*proxyFixture, string, int64) {
	t.Helper()
	f := newProxyFixture(t)
	journal, hold := journalOnly(settledOnce(t, f, "idem-reconcile", map[string]any{"max_tokens": 4000}))
	f.writeLog(t, journal)
	f.restart(t)
	if f.server.ReplaySummary().PendingDispatches != 1 {
		t.Fatalf("pending = %d, want 1", f.server.ReplaySummary().PendingDispatches)
	}
	return f, journal[0].SpendIntentID, hold
}

func (f *proxyFixture) reconcileOptions(t *testing.T, intent string) ReconcileOptions {
	t.Helper()
	cfg, sourceHash, err := LoadConfig(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	return ReconcileOptions{Config: cfg, SourceHash: sourceHash, ReceiptsDir: f.receiptsDir, SpendIntentID: intent,
		SigningSecret: "0101010101010101010101010101010101010101010101010101010101010101", Logf: t.Logf}
}

// TestReconcileSettlesAPendingHoldWithSignedLines (helm-tracker#313 r1, F11):
// an operator settles a pending dispatch at the provider cost found; the usage
// and settlement lines carry the reason, verify against the issuer key, and
// the next start debits them instead of holding the dispatch.
func TestReconcileSettlesAPendingHoldWithSignedLines(t *testing.T) {
	f, intent, hold := pendingFixture(t)
	_ = f.server.Close()
	opts := f.reconcileOptions(t, intent)
	opts.SettleCents, opts.Reason = 3, "provider console shows 3 cents"
	res, err := Reconcile(opts)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Action != "settled" || res.HoldCents != hold || res.DebitedCents != 3 {
		t.Fatalf("result = %+v", res)
	}
	f.start(t)
	if f.server.ReplaySummary().PendingDispatches != 0 || f.server.ledger.HoldCents() != 0 || 2000-f.server.BalanceCents() != 3 {
		t.Fatalf("after reconcile: pending %d, hold %d, debited %d", f.server.ReplaySummary().PendingDispatches, f.server.ledger.HoldCents(), 2000-f.server.BalanceCents())
	}
	pub, err := ParsePublicKey(f.server.SigningPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	results, err := ExportEvidencePacks(ExportOptions{ReceiptsDir: f.receiptsDir, OutDir: filepath.Join(t.TempDir(), "out"), PublicKey: pub})
	if err != nil || len(results) != 1 || !slices.Contains(results[0].SignaturesChecked, "usage") || !slices.Contains(results[0].SignaturesChecked, "settlement") {
		t.Fatalf("export = %+v, %v; want the reconciled lines verified", results, err)
	}
	for _, rec := range f.records(t) {
		if rec.Kind == RecordUsage && rec.Usage.Metadata[MetadataReconcileReason] != opts.Reason {
			t.Fatalf("the usage receipt does not carry the reason: %v", rec.Usage.Metadata)
		}
	}
	if _, err := Reconcile(opts); err == nil {
		t.Fatal("a settled dispatch was reconciled again")
	}
}

// TestReconcileReleasesAPendingHold (F11): an operator who finds the provider
// did not bill a dispatch releases its hold with a reason, journalled and
// signed; the key may then dispatch again.
func TestReconcileReleasesAPendingHold(t *testing.T) {
	f, intent, _ := pendingFixture(t)
	_ = f.server.Close()
	opts := f.reconcileOptions(t, intent)
	opts.Release, opts.Reason = true, "provider shows no such request"
	if res, err := Reconcile(opts); err != nil || res.Action != "released" {
		t.Fatalf("reconcile: %+v, %v", res, err)
	}
	f.start(t)
	if f.server.ReplaySummary().PendingDispatches != 0 || f.held() != 0 {
		t.Fatalf("after release: pending %d, held %d", f.server.ReplaySummary().PendingDispatches, f.held())
	}
	var release *ReceiptRecord
	for _, rec := range f.records(t) {
		if rec.Kind == RecordDispatchReleased {
			release = rec
		}
	}
	if release == nil || release.PayloadSignature == "" || !strings.Contains(release.RouteQuote.Metadata[MetadataReleaseReason], opts.Reason) {
		t.Fatalf("release line = %+v", release)
	}
	pub, _ := ParsePublicKey(f.server.SigningPublicKey())
	if err := verifyDetached(pub, release.Payload(), release.PayloadSignature); err != nil {
		t.Fatalf("the release line does not verify: %v", err)
	}
}

// TestReconcileNeedsTheProxysKey (F11): the lines a reconcile appends are
// signed by the key that signed the dispatch, or not at all.
func TestReconcileNeedsTheProxysKey(t *testing.T) {
	f, intent, _ := pendingFixture(t)
	_ = f.server.Close()
	opts := f.reconcileOptions(t, intent)
	opts.SigningSecret = "0909090909090909090909090909090909090909090909090909090909090909"
	opts.Release, opts.Reason = true, "x"
	if _, err := Reconcile(opts); err == nil || !strings.Contains(err.Error(), "signed by key") {
		t.Fatalf("reconcile with another key = %v", err)
	}
	f.start(t)
	if f.server.ReplaySummary().PendingDispatches != 1 {
		t.Fatal("a refused reconcile changed the log")
	}
}
