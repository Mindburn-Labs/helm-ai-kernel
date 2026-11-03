package inferencegateway

import (
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// TestRestoreSettlementRejectsTamperedReceipts ensures a mutated receipt (whose
// canonical content hash no longer matches) cannot be restored.
func TestRestoreSettlementRejectsTamperedReceipts(t *testing.T) {
	h := newHarness(t)
	quote, err := h.engine.Quote(h.env, h.req("idem-tamper", "gpt-6-sol", 1000, 500))
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
	otherQuote, err := h.engine.Quote(h.env, h.req("idem-tamper-2", "gpt-6-sol", 1000, 500))
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
