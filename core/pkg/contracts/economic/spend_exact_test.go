package economic

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func exactUsageFixture(t *testing.T, tokens int64) (*UsageReceiptV2, *ProviderPriceSnapshot) {
	t.Helper()
	p := exactPriceFixture()
	if err := p.Seal(); err != nil {
		t.Fatal(err)
	}
	amount, err := p.ExactCostNanoCents(tokens, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := &UsageReceiptV2{SchemaVersion: UsageReceiptSchemaV2, ID: "usage-1", TenantID: "tenant-1", WorkspaceID: "workspace-1", RouteQuoteID: "quote-1", SpendIntentID: "intent-1", EnvelopeID: "envelope-1", AgentID: "agent-1", ProviderID: p.ProviderID, ModelID: p.ModelID, ProviderRequestID: "request-1", ProviderPriceSnapshotHash: p.ContentHash, ObservationDigest: "sha256:" + strings.Repeat("b", 64), ReservedNanoCents: NanoCentsPerCent, AccruedNanoCents: amount, Currency: "USD", CostBasis: TariffEstimateBasis, InputTokens: tokens, PolicyHash: "sha256:" + strings.Repeat("c", 64), EvidencePackRef: "evidence:1", CreatedAt: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)}
	if err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	return r, p
}

func exactSettlementFixture(t *testing.T, r *UsageReceiptV2) *SettlementReceiptV2 {
	t.Helper()
	s := &SettlementReceiptV2{SchemaVersion: SettlementReceiptSchemaV2, ID: "settlement-1", TenantID: r.TenantID, WorkspaceID: r.WorkspaceID, UsageReceiptID: r.ID, RouteQuoteID: r.RouteQuoteID, SourceUsageReceiptHash: r.ContentHash, ReservedNanoCents: r.ReservedNanoCents, AccruedNanoCents: r.AccruedNanoCents, Currency: r.Currency, CostBasis: TariffEstimateBasis, LedgerEntries: []SettlementLedgerEntryV2{}, EvidencePackRef: r.EvidencePackRef, CreatedAt: r.CreatedAt}
	if r.AccruedNanoCents > 0 {
		s.LedgerEntries = []SettlementLedgerEntryV2{{"debit-1", "account-1", SettlementDebit, r.AccruedNanoCents}, {"credit-1", "accrual-1", SettlementCredit, r.AccruedNanoCents}}
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestExactAccrualConservesOneThousandTinyCalls(t *testing.T) {
	p := exactPriceFixture()
	b := ExactSpendBalance{LimitNanoCents: 2 * NanoCentsPerCent}
	for i := 0; i < 1000; i++ {
		var err error
		b, err = b.Reserve(NanoCentsPerCent)
		if err != nil {
			t.Fatal(err)
		}
		amount, err := p.ExactCostNanoCents(1, 0)
		if err != nil {
			t.Fatal(err)
		}
		b, err = b.Settle(NanoCentsPerCent, amount)
		if err != nil {
			t.Fatal(err)
		}
	}
	batch, err := p.ExactCostNanoCents(1000, 0)
	if err != nil || b.ConsumedNanoCents != 4_200_000 || b.ConsumedNanoCents != batch || b.ReservedNanoCents != 0 {
		t.Fatalf("accrual lost precision: %+v batch=%d err=%v", b, batch, err)
	}
}

func TestExactBalanceRejectsOverflowOverageAndDoubleRelease(t *testing.T) {
	for _, cents := range []int64{-1, math.MaxInt64/NanoCentsPerCent + 1} {
		if _, err := CentsToNanoCents(cents); err == nil {
			t.Fatal("invalid conversion accepted")
		}
	}
	b := ExactSpendBalance{LimitNanoCents: math.MaxInt64, ConsumedNanoCents: math.MaxInt64 - 100, ReservedNanoCents: 100}
	if next, err := b.Reserve(1); err == nil || next != b {
		t.Fatal("reservation overflow changed state")
	}
	for _, pair := range [][2]int64{{101, 1}, {100, 101}, {0, 0}, {100, -1}} {
		if next, err := b.Settle(pair[0], pair[1]); err == nil || next != b {
			t.Fatal("invalid settlement changed state")
		}
	}
	next, err := b.Settle(100, 0)
	if err != nil || next.ReservedNanoCents != 0 || next.ConsumedNanoCents != b.ConsumedNanoCents {
		t.Fatal("zero accrual did not release hold")
	}
	if _, err := next.Settle(100, 0); err == nil {
		t.Fatal("double release accepted")
	}
}

func TestExactReceiptsBindUsagePriceAndLedger(t *testing.T) {
	for _, tokens := range []int64{0, 1, 1000} {
		r, p := exactUsageFixture(t, tokens)
		s := exactSettlementFixture(t, r)
		if err := r.VerifyPrice(p); err != nil {
			t.Fatal(err)
		}
		if err := s.VerifyUsage(r); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(r)
		if decoded, err := DecodeUsageReceiptV2(raw); err != nil || !decoded.HasCanonicalContentHash() {
			t.Fatalf("usage roundtrip: %v", err)
		}
		raw, _ = json.Marshal(s)
		if decoded, err := DecodeSettlementReceiptV2(raw); err != nil || !decoded.HasCanonicalContentHash() {
			t.Fatalf("settlement roundtrip: %v", err)
		}
		p.InputTokenNanoCents++
		if r.VerifyPrice(p) == nil {
			t.Fatal("changed tariff accepted")
		}
		r.WorkspaceID = "different"
		if err := r.Seal(); err != nil {
			t.Fatal(err)
		}
		if s.VerifyUsage(r) == nil {
			t.Fatal("cross-workspace usage accepted")
		}
	}
}

func TestExactReceiptDecoderRejectsAmbiguousMoney(t *testing.T) {
	r, _ := exactUsageFixture(t, 1)
	raw, _ := json.Marshal(r)
	for _, bad := range []string{
		strings.Replace(string(raw), `"input_tokens":"1"`, `"input_tokens":1`, 1),
		strings.Replace(string(raw), `"input_tokens":"1"`, `"input_tokens":"01"`, 1),
		strings.Replace(string(raw), `"input_tokens":"1"`, `"input_tokens":null`, 1),
		strings.Replace(string(raw), `"input_tokens":"1",`, ``, 1),
		strings.Replace(string(raw), `"input_tokens":"1"`, `"input_tokens":"2","input_tokens":"1"`, 1),
		strings.Replace(string(raw), `"input_tokens":"1"`, `"actual_amount_cents":1,"input_tokens":"1"`, 1),
		string(raw) + `{}`,
	} {
		if _, err := DecodeUsageReceiptV2([]byte(bad)); err == nil {
			t.Fatalf("ambiguous JSON accepted: %s", bad)
		}
	}
}

func TestExactSettlementRejectsOffsettingAndOverflow(t *testing.T) {
	r, _ := exactUsageFixture(t, 1)
	for _, mutate := range []func(*SettlementReceiptV2){
		func(s *SettlementReceiptV2) { s.LedgerEntries[1].AccountID = s.LedgerEntries[0].AccountID },
		func(s *SettlementReceiptV2) { s.LedgerEntries[1].ID = s.LedgerEntries[0].ID },
		func(s *SettlementReceiptV2) { s.LedgerEntries[0].AmountNanoCents++ },
		func(s *SettlementReceiptV2) { s.LedgerEntries[0].Direction = "UNKNOWN" },
		func(s *SettlementReceiptV2) {
			s.LedgerEntries = append(s.LedgerEntries, SettlementLedgerEntryV2{"extra", "account-1", SettlementDebit, math.MaxInt64})
		},
	} {
		s := exactSettlementFixture(t, r)
		mutate(s)
		if s.Seal() == nil {
			t.Fatal("invalid settlement accepted")
		}
	}
}

func TestExactReceiptDigestCoversObservedUsage(t *testing.T) {
	r, _ := exactUsageFixture(t, 1)
	for _, mutate := range []func(*UsageReceiptV2){
		func(r *UsageReceiptV2) { r.InputTokens++ },
		func(r *UsageReceiptV2) { r.ProviderRequestID += "changed" },
		func(r *UsageReceiptV2) { r.ObservationDigest = "sha256:" + strings.Repeat("d", 64) },
		func(r *UsageReceiptV2) { r.CreatedAt = r.CreatedAt.Add(time.Second) },
	} {
		copy := *r
		mutate(&copy)
		if copy.CanonicalContentHash() == r.ContentHash {
			t.Fatal("uncommitted observation field")
		}
	}
}
