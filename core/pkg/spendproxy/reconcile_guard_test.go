package spendproxy

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// raiseOpening rewrites the fixture's config with a larger opening balance,
// as an operator does before reconciling a bill the balance could not cover.
func (f *proxyFixture) raiseOpening(t *testing.T, from, to string) {
	t.Helper()
	cfg, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	next := strings.Replace(string(cfg), `"opening_cents": `+from, `"opening_cents": `+to, 1)
	if next == string(cfg) {
		t.Fatalf("the config has no opening_cents %s", from)
	}
	if err := os.WriteFile(f.configPath, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestReconcileRefusesToReleaseABilledDispatch (helm-tracker#313 r2,
// finding 4): a dispatch whose settle_failed line records what the provider
// billed is not released: the release would erase spend the log proves.
func TestReconcileRefusesToReleaseABilledDispatch(t *testing.T) {
	f, _, intent := settleFailedOverage(t)
	_ = f.server.Close()
	opts := f.reconcileOptions(t, intent)
	opts.Release, opts.Reason = true, "operator thinks it was not billed"
	if res, err := Reconcile(opts); err == nil {
		t.Errorf("a billed dispatch was released: %+v", res)
	}
	f.start(t)
	if f.server.ReplaySummary().PendingDispatches != 1 || f.server.BalanceCents() != 60 {
		t.Fatalf("after the refused release: pending %d, balance %d; want the dispatch still held", f.server.ReplaySummary().PendingDispatches, f.server.BalanceCents())
	}
}

// TestReconcileSettlesAtLeastTheRecordedActual (finding 4): a settlement
// below the actual cost the log recorded is refused; at the recorded actual
// it settles.
func TestReconcileSettlesAtLeastTheRecordedActual(t *testing.T) {
	f, _, intent := settleFailedOverage(t)
	_ = f.server.Close()
	f.raiseOpening(t, "60", "20000")
	opts := f.reconcileOptions(t, intent)
	opts.SettleCents, opts.Reason = 1, "one cent will do"
	if res, err := Reconcile(opts); err == nil {
		t.Errorf("a settlement of 1 cent was accepted for a dispatch the log shows billed 5001: %+v", res)
	}
	opts.SettleCents, opts.Reason = 5001, "the provider console shows 5001 cents"
	res, err := Reconcile(opts)
	if err != nil || res.DebitedCents != 5001 {
		t.Fatalf("reconcile at the recorded actual: %+v, %v", res, err)
	}
}

// TestReconcileNeedsAReason (mutant N30): the library refuses a reconcile
// without a reason, as the CLI does.
func TestReconcileNeedsAReason(t *testing.T) {
	f, intent, _ := pendingFixture(t)
	_ = f.server.Close()
	opts := f.reconcileOptions(t, intent)
	opts.Release, opts.Reason = true, "  "
	if _, err := Reconcile(opts); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("reconcile without a reason: %v", err)
	}
}

// TestReconcileWorksInTheDefaultMode (finding 5): a proxy started without a
// signing seed keeps one generated seed in its receipts directory, mode 0600,
// so a restart signs under the same key and reconcile, also without a seed,
// signs with the key that signed the dispatch.
func TestReconcileWorksInTheDefaultMode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(testConfigJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := ""
	f := &proxyFixture{upstream: newMockUpstream(t), receiptsDir: filepath.Join(dir, "receipts"), configPath: configPath, secret: &empty}
	f.start(t)
	keyID := f.server.SigningKeyID()
	journal, _ := journalOnly(settledOnce(t, f, "idem-default", map[string]any{"max_tokens": 4000}))
	f.writeLog(t, journal)
	f.restart(t)
	if f.server.SigningKeyID() != keyID {
		t.Errorf("a restart in the default mode signs under %s, not %s", f.server.SigningKeyID(), keyID)
	}
	_ = f.server.Close()
	opts := f.reconcileOptions(t, journal[0].SpendIntentID)
	opts.SigningSecret = ""
	opts.Release, opts.Reason = true, "the provider has no such request"
	if _, err := Reconcile(opts); err != nil {
		t.Fatalf("reconcile in the default mode: %v", err)
	}
	info, err := os.Stat(filepath.Join(f.receiptsDir, "signing-seed"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the generated seed: %v, %v; want a file of mode 0600", info, err)
	}
}

// TestReconcileRefusesWhileTheProxyRuns (finding 14): reconcile takes the
// receipts directory's lock, which a running proxy holds.
func TestReconcileRefusesWhileTheProxyRuns(t *testing.T) {
	f, intent, _ := pendingFixture(t)
	opts := f.reconcileOptions(t, intent)
	opts.Release, opts.Reason = true, "the provider has no such request"
	if res, err := Reconcile(opts); err == nil {
		t.Fatalf("reconcile ran beside a live proxy: %+v", res)
	}
	if resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-alive", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("the proxy stopped serving: %d", resp.StatusCode)
	}
	_ = f.server.Close()
	if _, err := Reconcile(opts); err != nil {
		t.Fatalf("reconcile after the proxy stopped: %v", err)
	}
}

// TestASecondProxyRefusesTheReceiptsDir (finding 14): two proxies on one
// receipt log would both spend its balance; the second refuses to start.
func TestASecondProxyRefusesTheReceiptsDir(t *testing.T) {
	f := newProxyFixture(t)
	cfg, sourceHash, err := LoadConfig(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewServer(ServerOptions{Config: cfg, SourceHash: sourceHash, ReceiptsDir: f.receiptsDir,
		UpstreamBaseURL: f.upstream.server.URL + "/v1", UpstreamAPIKey: "k", SigningSecret: testSigningSeed, Logf: t.Logf})
	if err == nil {
		_ = second.Close()
		t.Fatal("a second proxy started on a receipts directory a running proxy holds")
	}
}
