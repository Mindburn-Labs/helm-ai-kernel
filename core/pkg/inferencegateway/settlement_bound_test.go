package inferencegateway

import (
	"errors"
	"math"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// TestReleasedReservationCannotSettle (helm-tracker#313 r1, F9): a released
// reservation means the provider was provably never called, so its quote can
// no longer be settled; on a 2-cent envelope the sequence admit a and b,
// settle a, release b, admit c, settle b would otherwise book 3 cents.
func TestReleasedReservationCannotSettle(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0 })
	env := twoCentEnvelope()
	a, okA, errA := admitOnce(h, env, "idem-a")
	b, okB, errB := admitOnce(h, env, "idem-b")
	if !okA || !okB || errA != nil || errB != nil {
		t.Fatalf("two 1-cent admissions against 2 cents: %v %v", errA, errB)
	}
	if _, err := h.engine.Settle(a.Quote, "prov-a", 1, 10, 10); err != nil {
		t.Fatalf("settle a: %v", err)
	}
	if _, err := h.engine.ReleaseReservation(b.Quote); err != nil {
		t.Fatalf("release b: %v", err)
	}
	if _, ok, err := admitOnce(h, env, "idem-c"); !ok || err != nil {
		t.Fatalf("admit c on the freed cent: %v", err)
	}
	if _, err := h.engine.Settle(b.Quote, "prov-b", 1, 10, 10); err == nil {
		t.Fatal("a released reservation was settled")
	}
	if consumed := h.ledger.envelopeConsumed(env, h.now); consumed > env.MaxAmountCents {
		t.Fatalf("the envelope holds %d cents against a %d-cent limit", consumed, env.MaxAmountCents)
	}
	if debited := 100_000 - h.ledger.BalanceCents(); debited != 1 {
		t.Fatalf("debited %d cents, want only a's 1", debited)
	}

	// On an envelope with room for it, a released quote is still not settled:
	// the release says the provider was never called.
	roomy := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0 })
	d, ok, err := admitOnce(roomy, roomy.env, "idem-d")
	if !ok || err != nil {
		t.Fatalf("admit d: %v", err)
	}
	if _, err := roomy.engine.ReleaseReservation(d.Quote); err != nil {
		t.Fatalf("release d: %v", err)
	}
	if _, err := roomy.engine.Settle(d.Quote, "prov-d", 1, 10, 10); err == nil || roomy.ledger.BalanceCents() != 100_000 {
		t.Fatalf("a released reservation was settled on an envelope with room (err %v, balance %d)", err, roomy.ledger.BalanceCents())
	}
}

// TestSettlementWithoutReservationIsDecidedAgainstTheEnvelope (F9): a
// settlement that no reservation backs is decided against its envelope like
// a reservation would be: it may not take the envelope past its limit.
func TestSettlementWithoutReservationIsDecidedAgainstTheEnvelope(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0 })
	env := twoCentEnvelope()
	for _, idem := range []string{"idem-1", "idem-2"} {
		if ok, err := spendOnce(h, env, idem); !ok || err != nil {
			t.Fatalf("%s: %v", idem, err)
		}
	}
	// A quote taken before the envelope was spent, settled without any
	// reservation.
	h2 := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0 })
	q, err := h2.engine.Quote(env, h2.req("idem-3", "gpt-6-sol", 10, 10))
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	if _, err := h.engine.Settle(q.Quote, "prov-3", 1, 10, 10); err == nil {
		t.Fatal("an unreserved settlement took the envelope past its limit")
	}
	if consumed := h.ledger.envelopeConsumed(env, h.now); consumed != 2 {
		t.Fatalf("the envelope holds %d cents, want 2", consumed)
	}
}

// TestSettlementAboveTheHoldClosesTheEnvelope (F2): with DEBIT_ACTUAL a bill
// above the hold is debited as billed; its usage receipt does not say the
// envelope covered it, and the envelope's window takes no further dispatch.
func TestSettlementAboveTheHoldClosesTheEnvelope(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) {
		c.PlatformFeeBps = 0
		c.CostCap = CostCapDebitActual
	})
	res, ok, err := admitOnce(h, h.env, "idem-over")
	if !ok || err != nil {
		t.Fatalf("admit: %v", err)
	}
	settled, err := h.engine.Settle(res.Quote, "prov-over", res.Quote.MaxAmountCents+40, 10, 10)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if settled.OverageCents != 40 || settled.BalanceDebitCents != res.Quote.MaxAmountCents+40 {
		t.Fatalf("settled %+v, want the bill debited with a 40-cent overage", settled)
	}
	if r := settled.UsageReceipt; r.ReasonCode == economic.SpendReasonOKWithinEnvelope || r.Metadata["envelope_closed"] == "" {
		t.Fatalf("the usage receipt of a bill above the hold says %s/%s, metadata %v", r.BudgetVerdict, r.ReasonCode, r.Metadata)
	}
	if !settled.UsageReceipt.HasCanonicalContentHash() {
		t.Fatal("the usage receipt is not sealed over what it says")
	}
	next, err := h.engine.Quote(h.env, h.req("idem-next", "gpt-6-sol", 10, 10))
	if err == nil {
		if _, err = h.engine.ReserveForDispatch(next); err == nil {
			t.Fatal("the envelope admitted a dispatch after a bill above its hold")
		}
	}
	var qe *QuoteError
	if !errors.As(err, &qe) || qe.ReasonCode != economic.SpendReasonEnvelopeInactive {
		t.Fatalf("refusal = %v, want ERR_SPEND_ENVELOPE_INACTIVE", err)
	}
}

// TestReservationRefusesAQuoteFromAnotherEngine (mutant M27): a quote result is
// reserved only by the engine and the envelope that issued it.
func TestReservationRefusesAQuoteFromAnotherEngine(t *testing.T) {
	h := newHarness(t)
	other := newHarness(t, func(c *EngineConfig) { c.RoutePolicyID = "another-policy" })
	res, err := other.engine.Quote(other.env, other.req("idem-foreign", "gpt-6-sol", 10, 10))
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	if _, err := h.engine.ReserveForDispatch(res); err == nil {
		t.Fatal("an engine reserved a quote another engine issued")
	}
	if h.ledger.HoldCents() != 0 {
		t.Fatalf("hold = %d, want 0", h.ledger.HoldCents())
	}
	own, err := h.engine.Quote(h.env, h.req("idem-own", "gpt-6-sol", 10, 10))
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	moved := buildEnvelope()
	moved.ID = "env-2"
	own.env = resealEnvelope(moved)
	if _, err := h.engine.ReserveForDispatch(own); err == nil {
		t.Fatal("a quote was reserved against an envelope it was not issued for")
	}
}

// TestRemainingCentsCannotWrap (F12): an envelope whose consumption saturates
// has nothing left, however much it also has reserved.
func TestRemainingCentsCannotWrap(t *testing.T) {
	env := buildEnvelope()
	env.MaxAmountCents = 1000
	env.ReservedAmountCents = 2000
	env = resealEnvelope(env)
	if got := effectiveEnvelope(env, math.MaxInt64).RemainingCents(); got != 0 {
		t.Fatalf("remaining = %d, want 0", got)
	}
}
