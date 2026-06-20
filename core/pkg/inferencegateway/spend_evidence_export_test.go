package inferencegateway

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

// TestSpendEvidencePackExportAndOfflineVerify drives a real governed Quote ->
// Settle through the engine, exports the four genuine SPEND3/5 receipts into a
// spend EvidencePack, and verifies that pack OFFLINE (no provider console). This
// is the SPEND8 end-to-end proof that the business views + offline verifier work
// against real engine output, not synthetic fixtures.
func TestSpendEvidencePackExportAndOfflineVerify(t *testing.T) {
	h := newHarness(t)

	quote, err := h.engine.Quote(h.env, h.req("idem-spend8", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("Quote() = %v", err)
	}
	if quote.Receipt == nil {
		t.Fatal("expected a budget verdict receipt on ALLOW")
	}

	settle, err := h.engine.Settle(quote.Quote, "prov-req-spend8", 2, 1000, 480)
	if err != nil {
		t.Fatalf("Settle() = %v", err)
	}

	set := evidencepack.SpendReceiptSet{
		RouteQuote: quote.Quote,
		Budget:     quote.Receipt,
		Usage:      settle.UsageReceipt,
		Settlement: settle.SettlementReceipt,
	}

	manifest, contents, err := evidencepack.BuildSpendEvidencePack(
		"pack-spend8", "did:helm:agent-1", quote.Quote.SpendIntentID,
		h.engine.RoutePolicyHash(), set, economic.DefaultRedactionProfile(),
	)
	if err != nil {
		t.Fatalf("build spend evidence pack: %v", err)
	}
	if manifest.ManifestHash == "" {
		t.Fatal("expected manifest hash on exported pack")
	}

	res, err := evidencepack.VerifySpendEvidenceOffline(contents)
	if err != nil {
		t.Fatalf("offline verify of real engine receipts failed: %v", err)
	}
	if !res.OK || !res.PromptBodyOffGraph || !res.Offline {
		t.Fatalf("unexpected offline verification result: %+v", res)
	}
	if len(res.ReceiptsVerified) != 4 {
		t.Fatalf("expected all 4 receipts verified, got %v", res.ReceiptsVerified)
	}

	// The business view layer must render and bind the settlement back to usage.
	usageView := economic.NewUsageReceiptView(settle.UsageReceipt, economic.DefaultRedactionProfile())
	if usageView.SettledVia != "BALANCE_DEBIT" {
		t.Fatalf("expected BALANCE_DEBIT for prepaid balance, got %s", usageView.SettledVia)
	}
	settlementView := economic.NewSettlementReceiptView(settle.SettlementReceipt, economic.DefaultRedactionProfile())
	if !settlementView.Balanced {
		t.Fatal("settlement view must be balanced")
	}
	if settlementView.SourceUsageReceiptHash != settle.UsageReceipt.ContentHash {
		t.Fatal("settlement view must bind the usage receipt content hash")
	}

	// The exported pack bytes must never contain a literal prompt body. The
	// engine receipts only store hashes, so the whole pack is prompt-free.
	for path, data := range contents {
		if strings.Contains(string(data), "123-45-6789") {
			t.Fatalf("unexpected sensitive payload in pack entry %s", path)
		}
	}
}
