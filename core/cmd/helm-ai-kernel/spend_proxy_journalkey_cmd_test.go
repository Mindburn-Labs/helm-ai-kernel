package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/spendproxy"
)

const changedSeed = "0303030303030303030303030303030303030303030303030303030303030303"

// startOnce starts and stops a spend proxy on receipts under seed, as an
// operator does after the seed changed: it registers the new key.
func startOnce(t *testing.T, config, receipts, seed string) {
	t.Helper()
	cfg, sourceHash, err := spendproxy.LoadConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := spendproxy.NewServer(spendproxy.ServerOptions{Config: cfg, SourceHash: sourceHash, ReceiptsDir: receipts,
		UpstreamBaseURL: "http://127.0.0.1:9/v1", UpstreamAPIKey: "k", SigningSecret: seed, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
}

func publicKeyHex(t *testing.T, seed string) string {
	t.Helper()
	issuer, _, err := spendproxy.NewIssuer(seed)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(issuer.PublicKey())
}

// TestSpendProxyReconcileSignsForARegisteredJournalKey (helm-tracker#313 r3,
// finding 2): after the seed changed, a dispatch journalled under the old key,
// which trusted_keys.json registers, is reconciled with the new seed, and
// export verifies the log against both keys given as --public-key.
func TestSpendProxyReconcileSignsForARegisteredJournalKey(t *testing.T) {
	config, receipts, intent, _ := pendingDispatch(t)
	startOnce(t, config, receipts, changedSeed)
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{"reconcile", "--config", config, "--receipts-dir", receipts, "--intent", intent,
		"--settle-cents", "3", "--reason", "the provider console shows the call", "--sign", changedSeed}, &stdout, &stderr); code != 0 {
		t.Fatalf("reconcile with the new seed: exit %d: %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code := runSpendProxyCmd([]string{"export", "--receipts-dir", receipts, "--out", t.TempDir(),
		"--public-key", publicKeyHex(t, reconcileSeed), "--public-key", publicKeyHex(t, changedSeed)}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "signatures verified") {
		t.Fatalf("export with both keys: exit %d: %s%s", code, stdout.String(), stderr.String())
	}
}

// TestSpendProxyReconcileAcknowledgesAnUnknownJournalKey (finding 2): when
// trusted_keys.json no longer registers the key that journalled a dispatch,
// reconcile with the current seed needs --journal-key-reason.
func TestSpendProxyReconcileAcknowledgesAnUnknownJournalKey(t *testing.T) {
	config, receipts, intent, _ := pendingDispatch(t)
	if err := os.Remove(filepath.Join(receipts, spendproxy.TrustedKeyFileName)); err != nil {
		t.Fatal(err)
	}
	startOnce(t, config, receipts, changedSeed)
	args := []string{"reconcile", "--config", config, "--receipts-dir", receipts, "--intent", intent,
		"--release", "--reason", "the provider has no such request", "--sign", changedSeed}
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd(args, &stdout, &stderr); code != 1 {
		t.Fatalf("reconcile without an acknowledgement: exit %d: %s", code, stderr.String())
	}
	stderr.Reset()
	if code := runSpendProxyCmd(append(args, "--journal-key-reason", "the old seed was lost with its key registry"), &stdout, &stderr); code != 0 {
		t.Fatalf("reconcile with --journal-key-reason: exit %d: %s", code, stderr.String())
	}
}
