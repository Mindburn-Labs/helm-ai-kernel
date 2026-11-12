package inferencegateway

import (
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// quoteAndReserve quotes a request of in/out tokens on gpt-6-sol and reserves
// it.
func quoteAndReserve(t *testing.T, h *harness, env *economic.AgentSpendEnvelope, idem string, in, out int64) *QuoteResult {
	t.Helper()
	res, err := h.engine.Quote(env, h.req(idem, "gpt-6-sol", in, out))
	if err != nil {
		t.Fatalf("quote %s: %v", idem, err)
	}
	if _, err := h.engine.ReserveForDispatch(res); err != nil {
		t.Fatalf("reserve %s: %v", idem, err)
	}
	return res
}

// TestPlatformFeeIsInsideTheHold (helm-tracker#313 r2, finding 1): the hold
// is the provider quote with the platform fee on it, so a provider that bills
// within its quote is debited no more than the hold, its receipt does not
// blame it, and the envelope stays open. Only a provider bill above the
// provider part of the hold is an overage.
func TestPlatformFeeIsInsideTheHold(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.CostCap = CostCapDebitActual }) // 1000 bps
	// 1000 input tokens at 500 and 5600 output tokens at 1500 micro-cents:
	// 8,900,000 micro-cents, a 9-cent provider quote.
	a := quoteAndReserve(t, h, h.env, "fee-a", 1000, 5600)
	if a.Quote.QuotedAmountCents != 9 || a.Quote.MaxAmountCents != 10 {
		t.Fatalf("quoted %d, hold %d; want the 9-cent provider quote held with its 10%% fee as 10 cents",
			a.Quote.QuotedAmountCents, a.Quote.MaxAmountCents)
	}
	// The provider bills its quote: 9 cents and a 0.9-cent fee.
	settled, err := h.engine.Settle(a.Quote, "prov-a", 9, 1000, 5600)
	if err != nil {
		t.Fatalf("settle a: %v", err)
	}
	if settled.OverageCents != 0 || settled.ActualAmountCents > a.Quote.MaxAmountCents {
		t.Fatalf("a bill within the quote debited %d cents (overage %d) against a %d-cent hold", settled.ActualAmountCents, settled.OverageCents, a.Quote.MaxAmountCents)
	}
	if r := settled.UsageReceipt; r.BudgetVerdict == economic.BudgetVerdictEscalate || r.Metadata["envelope_closed"] != "" {
		t.Fatalf("the receipt of a bill within the hold says %s/%s, metadata %v", r.BudgetVerdict, r.ReasonCode, r.Metadata)
	}

	// The provider bills the provider part of the hold (the split a debit
	// at the hold books, 10 cents and no fee): the fee is cut to the hold.
	b := quoteAndReserve(t, h, h.env, "fee-b", 1000, 5600)
	settled, err = h.engine.Settle(b.Quote, "prov-b", 10, 1000, 5600)
	if err != nil {
		t.Fatalf("settle b: %v", err)
	}
	if settled.OverageCents != 0 || settled.ActualAmountCents != b.Quote.MaxAmountCents || settled.UsageReceipt.BudgetVerdict == economic.BudgetVerdictEscalate {
		t.Fatalf("a provider bill at its part of the hold: actual %d, overage %d, verdict %s; want the hold, no overage", settled.ActualAmountCents, settled.OverageCents, settled.UsageReceipt.BudgetVerdict)
	}
	if next, err := h.engine.Quote(h.env, h.req("fee-next", "gpt-6-sol", 10, 10)); err != nil {
		t.Fatalf("the envelope refused a request after bills within their holds: %v", err)
	} else if _, err := h.engine.ReserveForDispatch(next); err != nil {
		t.Fatalf("the envelope refused a reservation after bills within their holds: %v", err)
	}

	// The provider bills above its part: that is the provider's overage.
	c := quoteAndReserve(t, h, h.env, "fee-c", 1000, 5600)
	settled, err = h.engine.Settle(c.Quote, "prov-c", 11, 1000, 5600)
	if err != nil {
		t.Fatalf("settle c: %v", err)
	}
	if settled.OverageCents != 2 || settled.UsageReceipt.BudgetVerdict != economic.BudgetVerdictEscalate || settled.UsageReceipt.Metadata["envelope_closed"] != h.env.ID {
		t.Fatalf("a provider bill above its part: overage %d, verdict %s, metadata %v; want 2 cents blamed on the provider", settled.OverageCents, settled.UsageReceipt.BudgetVerdict, settled.UsageReceipt.Metadata)
	}
}

// TestPlatformFeeFitsTheClampedOutput (finding 1): an output ceiling lowered
// to what the envelope can pay for leaves room for the fee, so the hold the
// reservation places is within the per-request limit.
func TestPlatformFeeFitsTheClampedOutput(t *testing.T) {
	h := newHarness(t) // 1000 bps
	env := buildEnvelope()
	env.MaxAmountCents, env.PerRequestMaxCents = 10, 10
	env = resealEnvelope(env)
	req := h.req("fee-clamp", "gpt-6-sol", 1000, 1_000_000)
	req.ClampOutputToMandate = true
	res, err := h.engine.Quote(env, req)
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	if res.Quote.MaxAmountCents > 10 {
		t.Fatalf("hold %d cents above the 10-cent per-request limit", res.Quote.MaxAmountCents)
	}
	if _, err := h.engine.ReserveForDispatch(res); err != nil {
		t.Fatalf("reserve the clamped quote: %v", err)
	}
}

// TestAnOverageClosesTheWindowItSettlesIn (finding 2): a dispatch reserved
// before a period boundary and settled above its hold after it closes the
// reservation's window and the window it settled in, and its usage receipt
// names both, so a restart closes the same ones.
func TestAnOverageClosesTheWindowItSettlesIn(t *testing.T) {
	start := time.Date(2026, 6, 20, 23, 59, 30, 0, time.UTC)
	clock := start
	prices := NewMemoryPriceBook()
	if err := prices.Put(buildSnapshot("price-openai-gpt", "openai", "gpt-6-sol", "terms-openai", "sha256:src-openai", start.Add(-time.Hour), start.Add(48*time.Hour), 500, 1500)); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *EngineConfig) {
		c.PlatformFeeBps = 0
		c.CostCap = CostCapDebitActual
		c.Prices = prices
		c.Now = fixedClock(&clock)
	})
	env := buildEnvelope()
	env.MaxAmountCents, env.PerRequestMaxCents = 10, 10
	env = resealEnvelope(env)
	a := quoteAndReserve(t, h, env, "window-a", 10, 10)
	clock = clock.Add(time.Minute) // 00:00:30 the next day
	settled, err := h.engine.Settle(a.Quote, "prov-a", 9, 10, 10)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	meta := settled.UsageReceipt.Metadata
	if meta["envelope_window"] != "2026-06-20" || meta["envelope_closed_windows"] != "2026-06-20,2026-06-21" {
		t.Errorf("usage metadata %v: want the debit booked in 2026-06-20 and both windows closed", meta)
	}
	next, err := h.engine.Quote(env, h.req("window-b", "gpt-6-sol", 10, 10))
	if err == nil {
		_, err = h.engine.ReserveForDispatch(next)
	}
	var qe *QuoteError
	if !errors.As(err, &qe) || qe.ReasonCode != economic.SpendReasonEnvelopeInactive {
		t.Errorf("the window the overage settled in admitted a dispatch: %v", err)
	}
}

// TestEnvelopeClosedOnlyWithAReservation (mutant N35): an overage no
// reservation backs closes no window and its receipt names none; the
// envelope_closed metadata is the record of a closure that happened.
func TestEnvelopeClosedOnlyWithAReservation(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) {
		c.PlatformFeeBps = 0
		c.CostCap = CostCapDebitActual
	})
	// The envelope is evaluated (so an unreserved settlement can be decided),
	// but the quote is never reserved.
	res, err := h.engine.Quote(h.env, h.req("unreserved", "gpt-6-sol", 10, 10))
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	settled, err := h.engine.Settle(res.Quote, "prov-u", res.Quote.MaxAmountCents+5, 10, 10)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if settled.OverageCents != 5 {
		t.Fatalf("overage = %d, want 5", settled.OverageCents)
	}
	if closed := settled.UsageReceipt.Metadata["envelope_closed"]; closed != "" {
		t.Fatalf("the receipt says envelope %s was closed, and no reservation closed it", closed)
	}
	if h.ledger.envelopeState(h.env, h.now).closed {
		t.Fatal("an unreserved overage closed the envelope")
	}
}

// TestSettleAtHoldDebitsTheFeeInclusiveHold (finding 1, mutant M28): a
// dispatch settled at its hold debits the whole hold, the provider's part and
// the fee on it, never only the provider's part.
func TestSettleAtHoldDebitsTheFeeInclusiveHold(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.CostCap = CostCapDebitActual }) // 1000 bps
	res := quoteAndReserve(t, h, h.env, "at-hold", 1000, 5600)
	settled, err := h.engine.SettleAtHold(res.Quote, "", "the provider answered without usage", nil)
	if err != nil {
		t.Fatalf("settle at hold: %v", err)
	}
	u := settled.UsageReceipt
	if settled.BalanceDebitCents != res.Quote.MaxAmountCents || u.ProviderCostCents != 10 || u.PlatformFeeCents != 0 {
		t.Fatalf("debited %d (provider %d, fee %d) on a %d-cent hold; want the hold, split as 10 and 0", settled.BalanceDebitCents, u.ProviderCostCents, u.PlatformFeeCents, res.Quote.MaxAmountCents)
	}
	big := quoteAndReserve(t, h, h.env, "at-hold-big", 10_000, 100_000)
	settled, err = h.engine.SettleAtHold(big.Quote, "", "the provider answered without usage", nil)
	if err != nil {
		t.Fatalf("settle at hold: %v", err)
	}
	u = settled.UsageReceipt
	if settled.BalanceDebitCents != big.Quote.MaxAmountCents || u.PlatformFeeCents == 0 || u.ProviderCostCents+u.PlatformFeeCents != big.Quote.MaxAmountCents {
		t.Fatalf("debited %d (provider %d, fee %d) on a %d-cent hold; want the whole hold with its fee", settled.BalanceDebitCents, u.ProviderCostCents, u.PlatformFeeCents, big.Quote.MaxAmountCents)
	}
}
