package spendproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tryStart starts the proxy as start does and returns the error instead of
// failing the test.
func (f *proxyFixture) tryStart(t *testing.T) error {
	t.Helper()
	cfg, sourceHash, err := LoadConfig(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(ServerOptions{Config: cfg, SourceHash: sourceHash, ReceiptsDir: f.receiptsDir,
		UpstreamBaseURL: f.upstream.server.URL + "/v1", UpstreamAPIKey: "k", SigningSecret: testSigningSeed, Logf: t.Logf})
	if err == nil {
		_ = s.Close()
	}
	return err
}

func (f *proxyFixture) appendLine(t *testing.T, rec *ReceiptRecord) {
	t.Helper()
	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	fh, err := os.OpenFile(filepath.Join(f.receiptsDir, ReceiptLogName), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if _, err := fh.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
}

// TestStartRefusesAnUnsignedReleaseLine (helm-tracker#313 r2, finding 9): a
// dispatch_released line nobody signed would free a pending hold on the next
// start; the start refuses the log instead, naming the line.
func TestStartRefusesAnUnsignedReleaseLine(t *testing.T) {
	f, intent, hold := pendingFixture(t)
	var journal *ReceiptRecord
	for _, rec := range f.records(t) {
		if rec.SpendIntentID == intent && rec.Kind == RecordRouteQuote {
			journal = rec
		}
	}
	_ = f.server.Close()
	f.appendLine(t, releaseRecord(journal.RouteQuote, "forged"))
	err := f.tryStart(t)
	if err == nil || !strings.Contains(err.Error(), "dispatch_released") {
		t.Fatalf("start with an unsigned release line: %v; want a refusal naming it (the hold was %d cents)", err, hold)
	}
}

// TestStartRefusesALineSignedByAnUnknownKey (finding 9): a usage line signed
// by a key the proxy does not know is refused too.
func TestStartRefusesALineSignedByAnUnknownKey(t *testing.T) {
	f := newProxyFixture(t)
	records := settledOnce(t, f, "idem-foreign-key", nil)
	_ = f.server.Close()
	foreign, _, err := NewIssuer("0909090909090909090909090909090909090909090909090909090909090909")
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range records {
		if rec.Kind == RecordUsage {
			rec.Usage.OutputTokens = 1
			rec.PayloadSignatureKeyID, rec.PayloadSignature, err = foreign.SignDetached(rec.Usage)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	f.writeLog(t, records)
	if err := f.tryStart(t); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("start with a usage line signed by an unknown key: %v", err)
	}
}
