package spendproxy

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// startInDefaultMode starts the proxy as start does without --sign and
// returns the error instead of failing the test.
func (f *proxyFixture) startInDefaultMode(t *testing.T) error {
	t.Helper()
	cfg, sourceHash, err := LoadConfig(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(ServerOptions{Config: cfg, SourceHash: sourceHash, ReceiptsDir: f.receiptsDir,
		UpstreamBaseURL: f.upstream.server.URL + "/v1", UpstreamAPIKey: "k", Logf: t.Logf})
	if err == nil {
		_ = s.Close()
	}
	return err
}

// defaultModePending leaves one dispatch pending in a receipts directory
// whose proxy ran without --sign, and stops the proxy.
func defaultModePending(t *testing.T) (*proxyFixture, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(testConfigJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := ""
	f := &proxyFixture{upstream: newMockUpstream(t), receiptsDir: filepath.Join(dir, "receipts"), configPath: configPath, secret: &empty}
	f.start(t)
	journal, _ := journalOnly(settledOnce(t, f, "idem-seed-file", map[string]any{"max_tokens": 4000}))
	f.writeLog(t, journal)
	_ = f.server.Close()
	f.http.Close()
	return f, journal[0].SpendIntentID
}

// TestASigningSeedReadableByOthersIsRefused (helm-tracker#313 r3, mutant
// R24): a generated seed that others can read refuses the start and
// reconcile.
func TestASigningSeedReadableByOthersIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not say who can read a file on windows")
	}
	f, intent := defaultModePending(t)
	if err := os.Chmod(filepath.Join(f.receiptsDir, SigningSeedFileName), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.startInDefaultMode(t); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Errorf("start with a seed of mode 0644: %v", err)
	}
	opts := f.reconcileOptions(t, intent)
	opts.SigningSecret, opts.Release, opts.Reason = "", true, "x"
	if _, err := Reconcile(opts); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Errorf("reconcile with a seed of mode 0644: %v", err)
	}
}

// TestASymlinkedSigningSeedIsRefused (note 6): the generated seed must be a
// regular file in the receipts directory, not a link to a seed elsewhere.
func TestASymlinkedSigningSeedIsRefused(t *testing.T) {
	f, intent := defaultModePending(t)
	seed := filepath.Join(f.receiptsDir, SigningSeedFileName)
	elsewhere := filepath.Join(t.TempDir(), "another-seed")
	if err := os.WriteFile(elsewhere, []byte(strings.Repeat("04", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(seed); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, seed); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if err := f.startInDefaultMode(t); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("start with a symlinked seed: %v", err)
	}
	opts := f.reconcileOptions(t, intent)
	opts.SigningSecret, opts.Release, opts.Reason = "", true, "x"
	if _, err := Reconcile(opts); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("reconcile with a symlinked seed: %v", err)
	}
}

// TestStartRefusesAnUnsignedSettleFailedLine (note 4): a settle_failed line
// closes envelope windows and sets the floor reconcile settles at, so a start
// verifies it as it verifies the lines that debit or free a hold.
func TestStartRefusesAnUnsignedSettleFailedLine(t *testing.T) {
	f, intent, _ := pendingFixture(t)
	journal := f.records(t)[0]
	_ = f.server.Close()
	f.http.Close()
	f.appendLine(t, &ReceiptRecord{Kind: RecordSettleFailed, TenantID: journal.TenantID, SpendIntentID: intent,
		Note: "settlement failed after dispatch: actual 900 cents not debited", RouteQuote: journal.RouteQuote})
	if err := f.tryStart(t); err == nil || !strings.Contains(err.Error(), "settle_failed") {
		t.Fatalf("start with an unsigned settle_failed line: %v", err)
	}
}

// TestStartRefusesALineWhoseSignatureDoesNotVerify (mutant R17): a release
// line signed by the proxy's key and edited after signing is refused.
func TestStartRefusesALineWhoseSignatureDoesNotVerify(t *testing.T) {
	f, intent, _ := pendingFixture(t)
	journal := f.records(t)[0]
	release := releaseRecord(journal.RouteQuote, "the provider has no such request")
	if err := f.server.signRecord(release); err != nil {
		t.Fatal(err)
	}
	release.RouteQuote.Metadata[MetadataReleaseReason] = "edited after signing"
	_ = f.server.Close()
	f.http.Close()
	f.appendLine(t, release)
	if err := f.tryStart(t); err == nil || !strings.Contains(err.Error(), "does not verify") || !strings.Contains(err.Error(), intent) {
		t.Fatalf("start with an edited release line: %v", err)
	}
}

// TestReconcileReadsALegacySettleFailedNote (mutant R21): a settle_failed
// line written before it carried the actual cost signed records it in its
// note; reconcile settles at no less than that.
func TestReconcileReadsALegacySettleFailedNote(t *testing.T) {
	f, intent, _ := pendingFixture(t)
	journal := f.records(t)[0]
	legacy := &ReceiptRecord{Kind: RecordSettleFailed, TenantID: journal.TenantID, SpendIntentID: intent,
		Note: "settlement failed after dispatch (DENY/ERR_SETTLEMENT_MISSING): actual 777 cents not debited", RouteQuote: journal.RouteQuote}
	if err := f.server.signRecord(legacy); err != nil {
		t.Fatal(err)
	}
	_ = f.server.Close()
	f.http.Close()
	f.appendLine(t, legacy)
	opts := f.reconcileOptions(t, intent)
	opts.SettleCents, opts.Reason = 700, "seven dollars"
	if res, err := Reconcile(opts); err == nil || !strings.Contains(err.Error(), "777") {
		t.Fatalf("a settlement of 700 cents against a legacy note of 777: %+v, %v", res, err)
	}
	opts.SettleCents = 777
	if res, err := Reconcile(opts); err != nil || res.DebitedCents != 777 {
		t.Fatalf("a settlement at the legacy note's 777 cents: %+v, %v", res, err)
	}
}

// TestReconcileComparesTheDebitWithTheRecordedActual (mutant R22): with a
// platform fee, the recorded actual is the provider's bill and the fee on it,
// and --settle-cents names the provider's bill: settling at it debits the
// recorded actual and is accepted.
func TestReconcileComparesTheDebitWithTheRecordedActual(t *testing.T) {
	cfg := strings.Replace(overageConfig(), `"platform_fee_bps": 0,`, `"platform_fee_bps": 1000,`, 1)
	var calls atomic.Int64
	f := newProxyFixtureWithUpstream(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		replyWithUsage("", 1_000_000, 16)(w, r)
	})
	if status, body := f.postRaw(t, "/v1/chat/completions", lostLineBody, "fee-reconcile"); status != http.StatusInternalServerError {
		t.Fatalf("status %d: %s; want the settlement to fail", status, body)
	}
	intent := ""
	for _, rec := range f.records(t) {
		if rec.Kind == RecordSettleFailed {
			intent = rec.SpendIntentID
			if rec.RouteQuote.Metadata[MetadataActualCents] != "5501" {
				t.Fatalf("the settle_failed line records %v, want an actual of 5501 cents", rec.RouteQuote.Metadata)
			}
		}
	}
	_ = f.server.Close()
	f.http.Close()
	f.raiseOpening(t, "60", "100000")
	opts := f.reconcileOptions(t, intent)
	opts.SettleCents, opts.Reason = 5001, "the provider console shows 5001 cents"
	if res, err := Reconcile(opts); err != nil || res.DebitedCents != 5501 {
		t.Fatalf("settling at the provider's 5001 cents: %+v, %v; want 5501 debited", res, err)
	}
}

// TestCallerIDsWithColonsDoNotShareKeys (mutant R27): a caller id may contain
// ':', so the scoped key carries the id's length: caller "team" with key
// "a:k" and caller "team:a" with key "k" are two dispatches.
func TestCallerIDsWithColonsDoNotShareKeys(t *testing.T) {
	cfg := strings.Replace(callerConfig(), `{"id": "live",`, `{"id": "team",`, 1)
	cfg = strings.Replace(cfg, `{"id": "replay",`, `{"id": "team:a",`, 1)
	f := newProxyFixtureWithConfig(t, cfg)
	if status, body := f.callerPost(t, callerTokenLive, "base-model", "a:k", nil); status != http.StatusOK {
		t.Fatalf("caller team: status %d (%s)", status, body)
	}
	if status, body := f.callerPost(t, callerTokenReplay, "mini-model", "k", map[string]string{"X-HELM-Spend-Envelope": "env-sub"}); status != http.StatusOK {
		t.Fatalf("caller team:a: status %d (%s)", status, body)
	}
	if f.upstream.calls.Load() != 2 {
		t.Fatalf("dispatches = %d, want one per caller", f.upstream.calls.Load())
	}
}

// TestABlankIdempotencyKeyIsMinted (note 3): a key that is only whitespace
// names no key, so the proxy mints one and each request is a new spend, with
// or without callers.
func TestABlankIdempotencyKeyIsMinted(t *testing.T) {
	const blank = " "
	for name, test := range map[string]struct {
		config, token string
	}{
		"callers":    {callerConfig(), callerTokenLive},
		"no callers": {testConfigJSON, ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := newProxyFixtureWithConfig(t, test.config)
			for i := range 2 {
				if status, body := f.callerPost(t, test.token, "base-model", blank, nil); status != http.StatusOK {
					t.Errorf("request %d with a blank key: status %d (%s)", i, status, body)
				}
			}
			if f.upstream.calls.Load() != 2 {
				t.Errorf("dispatches = %d, want two separate spends", f.upstream.calls.Load())
			}
		})
	}
}
