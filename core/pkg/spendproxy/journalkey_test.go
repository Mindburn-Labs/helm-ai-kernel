// quantum_posture: these tests check classical Ed25519 signatures of
// receipt lines through the spend proxy; no post-quantum claim is made.

package spendproxy

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedChangedAfterDispatch leaves one dispatch pending that a proxy run under
// seed journalled, then starts the proxy under the fixture's test seed, as an
// operator does whose seed was lost or changed: the first run's key stays
// registered in trusted_keys.json.
func seedChangedAfterDispatch(t *testing.T, seed string) (*proxyFixture, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(testConfigJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &proxyFixture{upstream: newMockUpstream(t), receiptsDir: filepath.Join(dir, "receipts"), configPath: configPath, secret: &seed}
	f.start(t)
	journal, _ := journalOnly(settledOnce(t, f, "idem-old-key", map[string]any{"max_tokens": 4000}))
	f.writeLog(t, journal)
	f.secret = nil
	f.restart(t)
	if f.server.ReplaySummary().PendingDispatches != 1 {
		t.Fatalf("pending = %d, want 1", f.server.ReplaySummary().PendingDispatches)
	}
	return f, journal[0].SpendIntentID
}

const otherSeed = "0909090909090909090909090909090909090909090909090909090909090909"

// TestReconcileSignsForAJournalUnderARegisteredKey (helm-tracker#313 r3,
// finding 2): a dispatch journalled under a key trusted_keys.json registers,
// such as the per-run key of a proxy run without --sign or the key of a lost
// seed, is reconciled with the current seed: the line is signed by the
// current key and names the journal's key, and the start warned about it.
func TestReconcileSignsForAJournalUnderARegisteredKey(t *testing.T) {
	f, intent := seedChangedAfterDispatch(t, otherSeed)
	old, _, err := NewIssuer(otherSeed)
	if err != nil {
		t.Fatal(err)
	}
	warned := false
	f.logMu.Lock()
	for _, line := range f.logs {
		if strings.Contains(line, "WARNING") && strings.Contains(line, old.KeyID()) && strings.Contains(line, intent) {
			warned = true
		}
	}
	f.logMu.Unlock()
	if !warned {
		t.Errorf("the start did not warn that intent %s was journalled under key %s", intent, old.KeyID())
	}
	_ = f.server.Close()
	f.http.Close()
	opts := f.reconcileOptions(t, intent)
	opts.Release, opts.Reason = true, "the provider has no such request"
	if _, err := Reconcile(opts); err != nil {
		t.Fatalf("reconcile of a dispatch journalled under a registered key: %v", err)
	}
	f.start(t)
	if f.server.ReplaySummary().PendingDispatches != 0 {
		t.Fatalf("pending after reconcile: %d", f.server.ReplaySummary().PendingDispatches)
	}
	for _, rec := range f.records(t) {
		if rec.Kind != RecordDispatchReleased {
			continue
		}
		if rec.PayloadSignatureKeyID != f.server.SigningKeyID() || rec.RouteQuote.Metadata["reconcile_journal_key_id"] != old.KeyID() {
			t.Errorf("the release line is signed by %s with metadata %v; want the current key %s naming the journal's key %s",
				rec.PayloadSignatureKeyID, rec.RouteQuote.Metadata, f.server.SigningKeyID(), old.KeyID())
		}
	}
}

// unknownJournalKey is seedChangedAfterDispatch after trusted_keys.json was
// lost: the proxy started again under the test seed registers only its key.
func unknownJournalKey(t *testing.T) (*proxyFixture, string) {
	t.Helper()
	f, intent := seedChangedAfterDispatch(t, otherSeed)
	_ = f.server.Close()
	f.http.Close()
	if err := os.Remove(filepath.Join(f.receiptsDir, TrustedKeyFileName)); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	_ = f.server.Close()
	f.http.Close()
	return f, intent
}

// TestReconcileRefusesAJournalUnderAnUnknownKey (finding 2): a dispatch
// journalled under a key trusted_keys.json does not register is not
// reconciled under another key without an acknowledgement.
func TestReconcileRefusesAJournalUnderAnUnknownKey(t *testing.T) {
	f, intent := unknownJournalKey(t)
	opts := f.reconcileOptions(t, intent)
	opts.Release, opts.Reason = true, "x"
	if _, err := Reconcile(opts); err == nil || !strings.Contains(err.Error(), "signed by key") {
		t.Fatalf("reconcile of a dispatch journalled under an unregistered key: %v", err)
	}
}

// TestReconcileAcknowledgesAnUnknownJournalKey (finding 2): with a reason the
// operator gives, reconcile signs for a dispatch journalled under a key
// trusted_keys.json does not register, and the line records the key and the
// reason; export then verifies the log only with both keys pinned.
func TestReconcileAcknowledgesAnUnknownJournalKey(t *testing.T) {
	f, intent := unknownJournalKey(t)
	old, _, err := NewIssuer(otherSeed)
	if err != nil {
		t.Fatal(err)
	}
	opts := f.reconcileOptions(t, intent)
	opts.SettleCents, opts.Reason = 3, "the provider console shows 3 cents"
	opts.JournalKeyReason = "the old seed was lost with its key registry"
	if _, err := Reconcile(opts); err != nil {
		t.Fatalf("reconcile with an acknowledgement: %v", err)
	}
	f.start(t)
	if f.server.ReplaySummary().PendingDispatches != 0 || f.held() != 3 {
		t.Fatalf("after reconcile: pending %d, %d cents kept", f.server.ReplaySummary().PendingDispatches, f.held())
	}
	for _, rec := range f.records(t) {
		if rec.Kind == RecordUsage && (rec.Usage.Metadata[MetadataReconcileJournalKey] != old.KeyID() || rec.Usage.Metadata[MetadataReconcileJournalKeyReason] != opts.JournalKeyReason) {
			t.Errorf("the usage receipt does not name the journal's key and the reason: %v", rec.Usage.Metadata)
		}
	}
	current, err := ParsePublicKey(f.server.SigningPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out")
	if _, err := ExportEvidencePacks(ExportOptions{ReceiptsDir: f.receiptsDir, OutDir: out, PublicKey: current}); err == nil || !strings.Contains(err.Error(), old.KeyID()) {
		t.Errorf("export with only the current key: %v; want the journal line refused, naming its key", err)
	}
	results, err := ExportEvidencePacks(ExportOptions{ReceiptsDir: f.receiptsDir, OutDir: out, PublicKey: current, PublicKeys: []ed25519.PublicKey{old.PublicKey()}})
	if err != nil || len(results) != 1 || !results[0].SignatureVerified || len(results[0].SignatureKeyIDs) != 2 {
		t.Fatalf("export with both keys: %+v, %v", results, err)
	}
}

// TestReconcileRefusesAnEditedJournalLine (finding 2): a journal line under a
// registered key that no longer verifies against it is not reconciled under
// another key without an acknowledgement.
func TestReconcileRefusesAnEditedJournalLine(t *testing.T) {
	f, intent := seedChangedAfterDispatch(t, otherSeed)
	_ = f.server.Close()
	f.http.Close()
	records := f.records(t)
	records[0].RouteQuote.Metadata = map[string]string{"edited": "after signing"}
	f.writeLog(t, records)
	opts := f.reconcileOptions(t, intent)
	opts.Release, opts.Reason = true, "x"
	if _, err := Reconcile(opts); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("reconcile of an edited journal line: %v", err)
	}
	opts.JournalKeyReason = "the operator checked the provider console"
	if _, err := Reconcile(opts); err != nil {
		t.Fatalf("reconcile of an edited journal line with an acknowledgement: %v", err)
	}
}
