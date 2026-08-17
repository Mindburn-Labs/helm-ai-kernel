package inferencegateway

import (
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// TestRestoreSettlementReplaysWithoutDoubleDebit simulates a process restart:
// receipts committed by a first engine are restored (via their JSON round-trip,
// as a durable store would hold them) into a fresh ledger whose opening balance
// already reflects the debit. Settling the same idempotency scope again must
// replay the original receipts without touching the balance.
func TestRestoreSettlementReplaysWithoutDoubleDebit(t *testing.T) {
	first := newHarness(t)
	quote, err := first.engine.Quote(first.env, first.req("idem-restore", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("Quote() = %v", err)
	}
	settle, err := first.engine.Settle(quote.Quote, "prov-req-restore", 100, 1000, 480)
	if err != nil {
		t.Fatalf("Settle() = %v", err)
	}

	// Round-trip the receipts through JSON exactly as a durable store would.
	usage := roundTripUsage(t, settle.UsageReceipt)
	settlement := roundTripSettlement(t, settle.SettlementReceipt)

	// "Restarted" ledger: opening balance minus the already-committed debit.
	account := economic.NewBalanceAccount("balance-1", "tenant-1", "USD",
		100_000-settle.BalanceDebitCents, "evidence://balance-1")
	ledger, err := NewBalanceLedger(account)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	if err := ledger.RestoreSettlement(usage, settlement, settle.BalanceAfterCents); err != nil {
		t.Fatalf("RestoreSettlement() = %v", err)
	}
	// Restoring the same settlement again is a no-op.
	if err := ledger.RestoreSettlement(usage, settlement, settle.BalanceAfterCents); err != nil {
		t.Fatalf("second RestoreSettlement() = %v", err)
	}

	second := newHarness(t, func(cfg *EngineConfig) { cfg.Ledger = ledger })
	replayQuote, err := second.engine.Quote(second.env, second.req("idem-restore", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("replay Quote() = %v", err)
	}
	replay, err := second.engine.Settle(replayQuote.Quote, "prov-req-restore-2", 100, 1000, 480)
	if err != nil {
		t.Fatalf("replay Settle() = %v", err)
	}
	if !replay.Replayed {
		t.Fatal("settle after restore must be an idempotent replay")
	}
	if replay.UsageReceipt.ContentHash != usage.ContentHash {
		t.Fatal("replay must return the restored usage receipt")
	}
	if replay.BalanceAfterCents != settle.BalanceAfterCents {
		t.Fatalf("replay balance_after = %d, want recorded %d", replay.BalanceAfterCents, settle.BalanceAfterCents)
	}
	if got := ledger.BalanceCents(); got != 100_000-settle.BalanceDebitCents {
		t.Fatalf("balance mutated by replay: %d", got)
	}
	if entries := len(ledger.Entries()); entries != 0 {
		t.Fatalf("replay must post no new ledger entries, got %d", entries)
	}
}

// TestRestoreSettlementRejectsTamperedReceipts ensures a mutated receipt (whose
// canonical content hash no longer matches) cannot be restored.
func TestRestoreSettlementRejectsTamperedReceipts(t *testing.T) {
	h := newHarness(t)
	quote, err := h.engine.Quote(h.env, h.req("idem-tamper", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("Quote() = %v", err)
	}
	settle, err := h.engine.Settle(quote.Quote, "prov-req-tamper", 100, 1000, 480)
	if err != nil {
		t.Fatalf("Settle() = %v", err)
	}

	account := economic.NewBalanceAccount("balance-2", "tenant-1", "USD", 50_000, "evidence://balance-2")
	ledger, err := NewBalanceLedger(account)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}

	tampered := roundTripUsage(t, settle.UsageReceipt)
	tampered.ProviderCostCents += 5
	tampered.ActualAmountCents += 5
	tampered.BalanceDebitCents += 5
	if err := ledger.RestoreSettlement(tampered, settle.SettlementReceipt, settle.BalanceAfterCents); err == nil {
		t.Fatal("tampered usage receipt must not restore")
	}

	// A settlement that does not bind the usage hash must also be refused.
	otherQuote, err := h.engine.Quote(h.env, h.req("idem-tamper-2", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("Quote() = %v", err)
	}
	otherSettle, err := h.engine.Settle(otherQuote.Quote, "prov-req-tamper-2", 100, 1000, 480)
	if err != nil {
		t.Fatalf("Settle() = %v", err)
	}
	if err := ledger.RestoreSettlement(settle.UsageReceipt, otherSettle.SettlementReceipt, settle.BalanceAfterCents); err == nil {
		t.Fatal("settlement binding a different usage receipt must not restore")
	}
}

func roundTripUsage(t *testing.T, in *economic.UsageReceipt) *economic.UsageReceipt {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal usage: %v", err)
	}
	out := &economic.UsageReceipt{}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("unmarshal usage: %v", err)
	}
	return out
}

func roundTripSettlement(t *testing.T, in *economic.SettlementReceipt) *economic.SettlementReceipt {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal settlement: %v", err)
	}
	out := &economic.SettlementReceipt{}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("unmarshal settlement: %v", err)
	}
	return out
}
