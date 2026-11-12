package spendproxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// writeLog replaces the receipt log with records.
func (f *proxyFixture) writeLog(t *testing.T, records []*ReceiptRecord) {
	t.Helper()
	var lines []string
	for _, rec := range records {
		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(line))
	}
	if err := os.WriteFile(filepath.Join(f.receiptsDir, ReceiptLogName), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// settledOnce runs one request to settlement and returns the fixture's log.
func settledOnce(t *testing.T, f *proxyFixture, idem string, extra map[string]any) []*ReceiptRecord {
	t.Helper()
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", idem, extra)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	return f.records(t)
}

// TestReceiptLogRefusesALineWhosePayloadIsNotItsKind (helm-tracker#313 r1,
// F1): a line carries exactly the payload its kind names. The forgery the
// review found, a usage line rewritten to 2 output tokens and covered with the
// journal's route_quote payload and signature, is refused when the log is
// read, so export never reports it verified.
func TestReceiptLogRefusesALineWhosePayloadIsNotItsKind(t *testing.T) {
	f := newProxyFixture(t)
	records := settledOnce(t, f, "idem-forge", nil)
	var journal *ReceiptRecord
	for _, rec := range records {
		if rec.Kind == RecordRouteQuote && rec.PayloadSignature != "" {
			journal = rec
		}
	}
	if journal == nil {
		t.Fatal("no signed route quote")
	}
	for _, rec := range records {
		if rec.Kind == RecordUsage {
			rec.Usage.OutputTokens, rec.Usage.InputTokens = 2, 1
			rec.RouteQuote = journal.RouteQuote
			rec.PayloadSignature, rec.PayloadSignatureKeyID = journal.PayloadSignature, journal.PayloadSignatureKeyID
		}
	}
	f.writeLog(t, records)
	pub, err := ParsePublicKey(f.server.SigningPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	results, err := ExportEvidencePacks(ExportOptions{ReceiptsDir: f.receiptsDir, OutDir: filepath.Join(t.TempDir(), "out"), PublicKey: pub})
	if err == nil {
		t.Fatalf("a forged usage line exported: %+v", results)
	}
	if !strings.Contains(err.Error(), "payload") {
		t.Fatalf("export refused with %v, want the line refused for a payload its kind does not name", err)
	}

	for name, mutate := range map[string]func(r *ReceiptRecord){
		"a usage line with no payload":         func(r *ReceiptRecord) { r.Kind, r.RouteQuote = RecordUsage, nil },
		"a route_quote line carrying usage":    func(r *ReceiptRecord) { r.Usage = &economic.UsageReceipt{ID: "u"}; r.RouteQuote = nil },
		"a route_quote line with two payloads": func(r *ReceiptRecord) { r.Settlement = &economic.SettlementReceipt{ID: "s"} },
		"an unknown kind":                      func(r *ReceiptRecord) { r.Kind = "receipt" },
	} {
		rec := *journal
		mutate(&rec)
		f.writeLog(t, []*ReceiptRecord{&rec})
		if _, err := LoadRecords(filepath.Join(f.receiptsDir, ReceiptLogName)); err == nil {
			t.Errorf("%s: the log was read", name)
		}
	}
}

// TestRecordPayloadIsPickedByKind (F1): the payload a line's signature covers
// is the one its kind names, whatever else the line carries.
func TestRecordPayloadIsPickedByKind(t *testing.T) {
	quote := &economic.RouteQuote{ID: "rq"}
	usage := &economic.UsageReceipt{ID: "u"}
	rec := &ReceiptRecord{Kind: RecordUsage, RouteQuote: quote, Usage: usage}
	if got, ok := rec.Payload().(*economic.UsageReceipt); !ok || got != usage {
		t.Fatalf("payload of a usage line = %#v, want its usage receipt", rec.Payload())
	}
	rec = &ReceiptRecord{Kind: RecordSettlement, RouteQuote: quote}
	if p := rec.Payload(); p != nil && fmt.Sprint(p) != "<nil>" {
		t.Fatalf("payload of a settlement line without a settlement = %#v, want none", p)
	}
}

// TestExportRefusesAnUnsignedRecord (mutant M37): with a pinned key, a line of
// the intent that carries no signature fails the export.
func TestExportRefusesAnUnsignedRecord(t *testing.T) {
	f := newProxyFixture(t)
	records := settledOnce(t, f, "idem-unsigned", nil)
	for _, rec := range records {
		if rec.Kind == RecordUsage {
			rec.PayloadSignature, rec.PayloadSignatureKeyID = "", ""
		}
	}
	f.writeLog(t, records)
	pub, err := ParsePublicKey(f.server.SigningPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExportEvidencePacks(ExportOptions{ReceiptsDir: f.receiptsDir, OutDir: filepath.Join(t.TempDir(), "out"), PublicKey: pub}); err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Fatalf("export = %v, want the unsigned usage line refused", err)
	}
}

// TestSettlementWithoutItsUsageLineIsHeldOnRestart (F10): a settlement line
// whose usage line never reached the log carries no debit; on restart the
// dispatch is held at its hold, pending reconciliation, instead of forgotten.
func TestSettlementWithoutItsUsageLineIsHeldOnRestart(t *testing.T) {
	f := newProxyFixture(t)
	records := settledOnce(t, f, "idem-lost", map[string]any{"max_tokens": 4000})
	var kept []*ReceiptRecord
	var hold int64
	for _, rec := range records {
		if rec.Kind == RecordRouteQuote && rec.RouteQuote != nil {
			hold = rec.RouteQuote.MaxAmountCents
		}
		if rec.Kind != RecordUsage {
			kept = append(kept, rec)
		}
	}
	f.writeLog(t, kept)
	f.restart(t)
	if f.held() != hold || f.server.ReplaySummary().PendingDispatches != 1 {
		t.Fatalf("after a restart the dispatch holds %d cents (pending %d), want its %d-cent hold", f.held(), f.server.ReplaySummary().PendingDispatches, hold)
	}
	if resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "idem-lost", map[string]any{"max_tokens": 4000}); resp.StatusCode != http.StatusConflict {
		t.Fatalf("retry status %d, want 409", resp.StatusCode)
	}
	if f.upstream.calls.Load() != 1 {
		t.Fatalf("the provider was called %d times", f.upstream.calls.Load())
	}
}

// TestRestartDoesNotHoldASettledDispatch (mutant M25): a dispatch whose usage
// and settlement are in the log is settled, not pending, after a restart.
func TestRestartDoesNotHoldASettledDispatch(t *testing.T) {
	f := newProxyFixture(t)
	settledOnce(t, f, "idem-settled", nil)
	debited := 2000 - f.server.BalanceCents()
	f.restart(t)
	if f.server.ReplaySummary().PendingDispatches != 0 || f.server.ledger.HoldCents() != 0 || 2000-f.server.BalanceCents() != debited {
		t.Fatalf("after a restart: pending %d, hold %d, debited %d; want 0, 0, %d",
			f.server.ReplaySummary().PendingDispatches, f.server.ledger.HoldCents(), 2000-f.server.BalanceCents(), debited)
	}
}

// journalOnly keeps the journal line of a settled run and drops the rest, as
// if the process stopped after journalling the dispatch.
func journalOnly(records []*ReceiptRecord) ([]*ReceiptRecord, int64) {
	for _, rec := range records {
		if rec.Kind == RecordRouteQuote && rec.Note == NoteDispatchJournal {
			return []*ReceiptRecord{rec}, rec.RouteQuote.MaxAmountCents
		}
	}
	return nil, 0
}

// TestRestoredHoldIsPlacedPastTheBalance (mutant M26): a dispatch journalled
// and never settled is held on start even when the balance can no longer
// cover it, because the provider may already have billed it.
func TestRestoredHoldIsPlacedPastTheBalance(t *testing.T) {
	f := newProxyFixture(t)
	journal, hold := journalOnly(settledOnce(t, f, "idem-past", map[string]any{"max_tokens": 4000}))
	if journal == nil || hold <= 10 {
		t.Fatalf("journal %v, hold %d", journal, hold)
	}
	f.writeLog(t, journal)
	cfg, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.configPath, []byte(strings.Replace(string(cfg), `"opening_cents": 2000`, `"opening_cents": 10`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	f.restart(t)
	if f.server.ledger.HoldCents() != hold || f.server.ReplaySummary().PendingCents != hold {
		t.Fatalf("hold after restart = %d, want the %d-cent hold above the 10-cent balance", f.server.ledger.HoldCents(), hold)
	}
}

// TestRestartHoldsALegacyJournalLine (mutant M32): a log written before the
// journal note existed carries none; an allowing, receipt-bound route_quote
// line with no settlement is still held on start.
func TestRestartHoldsALegacyJournalLine(t *testing.T) {
	f := newProxyFixture(t)
	journal, hold := journalOnly(settledOnce(t, f, "idem-legacy", nil))
	journal[0].Note = ""
	f.writeLog(t, journal)
	f.restart(t)
	if f.server.ledger.HoldCents() != hold || f.server.ReplaySummary().PendingDispatches != 1 {
		t.Fatalf("hold after restart = %d (pending %d), want %d", f.server.ledger.HoldCents(), f.server.ReplaySummary().PendingDispatches, hold)
	}
}

// TestRestartKeepsEnvelopeUse (mutant M31): what an envelope's settled
// dispatches used survives a restart, so the limit is not handed out again.
func TestRestartKeepsEnvelopeUse(t *testing.T) {
	f := newProxyFixtureWithConfig(t, twoCentConfig())
	for i := range 2 {
		if resp := f.post(t, "/v1/chat/completions", "mini-model", "env-direct", fmt.Sprintf("idem-use-%d", i), nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}
	f.restart(t)
	if resp := f.post(t, "/v1/chat/completions", "mini-model", "env-direct", "idem-use-after", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("after a restart a spent 2-cent envelope answered %d", resp.StatusCode)
	}
	if f.upstream.calls.Load() != 2 {
		t.Fatalf("dispatches = %d, want 2", f.upstream.calls.Load())
	}
}
