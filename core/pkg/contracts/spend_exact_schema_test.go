package contracts_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

func TestExactSpendReceiptSchemas(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	r := &economic.UsageReceiptV2{SchemaVersion: economic.UsageReceiptSchemaV2, ID: "usage-1", TenantID: "tenant-1", WorkspaceID: "workspace-1", RouteQuoteID: "quote-1", SpendIntentID: "intent-1", EnvelopeID: "envelope-1", AgentID: "agent-1", ProviderID: "typesafe", ModelID: "jev-fixture", ProviderRequestID: "request-1", ProviderPriceSnapshotHash: digest, ObservationDigest: digest, ReservedNanoCents: economic.NanoCentsPerCent, AccruedNanoCents: 4200, Currency: "USD", CostBasis: economic.TariffEstimateBasis, InputTokens: 1, PolicyHash: digest, EvidencePackRef: "evidence:1", CreatedAt: now}
	if err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	s := &economic.SettlementReceiptV2{SchemaVersion: economic.SettlementReceiptSchemaV2, ID: "settlement-1", TenantID: r.TenantID, WorkspaceID: r.WorkspaceID, UsageReceiptID: r.ID, RouteQuoteID: r.RouteQuoteID, SourceUsageReceiptHash: r.ContentHash, ReservedNanoCents: r.ReservedNanoCents, AccruedNanoCents: 4200, Currency: r.Currency, CostBasis: r.CostBasis, LedgerEntries: []economic.SettlementLedgerEntryV2{{ID: "debit-1", AccountID: "account-1", Direction: economic.SettlementDebit, AmountNanoCents: 4200}, {ID: "credit-1", AccountID: "accrual-1", Direction: economic.SettlementCredit, AmountNanoCents: 4200}}, EvidencePackRef: r.EvidencePackRef, CreatedAt: now}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		receipt any
	}{{"usage_receipt", r}, {"settlement_receipt", s}} {
		t.Run(c.name, func(t *testing.T) {
			schema := compileSchema(t, "spend/"+c.name+".v2.schema.json")
			raw, err := json.Marshal(c.receipt)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Fatal(err)
			}
			for key, value := range doc {
				delete(doc, key)
				if schema.Validate(doc) == nil {
					t.Fatalf("missing %s accepted", key)
				}
				doc[key] = value
			}
			for _, bad := range []any{4200, "-1", "01", "1.5", nil} {
				doc["accrued_nano_cents"] = bad
				if schema.Validate(doc) == nil {
					t.Fatalf("ambiguous amount %v accepted", bad)
				}
			}
			doc["accrued_nano_cents"] = "4200"
			doc["actual_amount_cents"] = 1
			if schema.Validate(doc) == nil {
				t.Fatal("mixed cent units accepted")
			}
		})
	}
}
