package inferencegateway

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// twoCentEnvelope is buildEnvelope with a 2-cent limit for the whole period.
func twoCentEnvelope() *economic.AgentSpendEnvelope {
	env := buildEnvelope()
	env.MaxAmountCents = 2
	env.PerRequestMaxCents = 2
	return resealEnvelope(env)
}

// admitOnce quotes and reserves one 1-cent request the way the governed
// gateway does. It reports whether the request was admitted, and checks that a
// budget-verdict receipt exists exactly when the reservation succeeded.
func admitOnce(h *harness, env *economic.AgentSpendEnvelope, idem string) (*QuoteResult, bool, error) {
	res, err := h.engine.Quote(env, h.req(idem, "gpt-6-sol", 10, 10))
	if err != nil {
		if res != nil && res.Receipt != nil {
			return nil, false, fmt.Errorf("%s: a refused quote carries a receipt", idem)
		}
		return nil, false, nil
	}
	if res.Receipt != nil {
		return nil, false, fmt.Errorf("%s: a receipt was issued before any reservation", idem)
	}
	if _, err := h.engine.ReserveForDispatch(res); err != nil {
		var qe *QuoteError
		if !errors.As(err, &qe) {
			return nil, false, fmt.Errorf("%s: reserve: %w", idem, err)
		}
		if res.Receipt != nil || res.Quote.BudgetVerdict != economic.BudgetVerdictDeny || res.Quote.ReceiptHash != "" {
			return nil, false, fmt.Errorf("%s: a refused reservation left an allowing quote or a receipt", idem)
		}
		return nil, false, nil
	}
	if res.Receipt == nil || res.Receipt.ReasonCode != economic.SpendReasonOKWithinEnvelope || res.Quote.ReceiptHash != res.Receipt.ContentHash {
		return nil, false, fmt.Errorf("%s: a reservation without its OK_WITHIN_ENVELOPE receipt", idem)
	}
	return res, true, nil
}

// spendOnce admits and settles one request at a 1-cent provider cost.
func spendOnce(h *harness, env *economic.AgentSpendEnvelope, idem string) (bool, error) {
	res, ok, err := admitOnce(h, env, idem)
	if err != nil || !ok {
		return false, err
	}
	if _, err := h.engine.Settle(res.Quote, "prov-"+idem, 1, 10, 10); err != nil {
		return true, fmt.Errorf("%s: settle: %w", idem, err)
	}
	return true, nil
}

// TestEnvelopeLimitIsConsumed (helm-tracker#313, audit H7): an envelope's
// max_amount_cents is spent by the requests it admits. With a 2-cent limit,
// ten 1-cent requests stop at the limit.
func TestEnvelopeLimitIsConsumed(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0 })
	env := twoCentEnvelope()
	allowed := 0
	for i := range 10 {
		ok, err := spendOnce(h, env, fmt.Sprintf("idem-env-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			allowed++
		}
	}
	debited := int64(100_000) - h.ledger.BalanceCents()
	if allowed != 2 || debited != 2 {
		t.Fatalf("a 2-cent envelope admitted %d requests and debited %d cents, want 2 and 2", allowed, debited)
	}
	if consumed := h.ledger.envelopeConsumed(env, h.now); consumed != 2 || h.ledger.HoldCents() != 0 {
		t.Fatalf("envelope consumed %d with %d held, want 2 used and nothing reserved", consumed, h.ledger.HoldCents())
	}
}

// TestConcurrentRequestsCannotBothTakeTheLastCents: check and reserve are one
// step, so concurrent requests against the same envelope cannot all pass.
func TestConcurrentRequestsCannotBothTakeTheLastCents(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0 })
	env := twoCentEnvelope()
	var mu sync.Mutex
	receipts := 0
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, ok, err := admitOnce(h, env, fmt.Sprintf("idem-race-%d", i))
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				mu.Lock()
				receipts++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	// Each quote holds 1 cent (10 in * 500 + 10 out * 1500 micro-cents, rounded
	// up), so exactly two can hold the 2-cent envelope at once.
	if receipts != 2 {
		t.Fatalf("%d concurrent requests hold an OK_WITHIN_ENVELOPE receipt and a reservation against a 2-cent envelope, want 2", receipts)
	}
	if consumed := h.ledger.envelopeConsumed(env, h.now); consumed != 2 || h.ledger.HoldCents() != 2 {
		t.Fatalf("envelope consumed %d with %d held, want 2 reserved", consumed, h.ledger.HoldCents())
	}
}

// TestReleaseFreesTheEnvelopeAndTheNextPeriodResets: a reservation released
// because the provider was never called gives its cents back; a daily
// envelope's limit starts again the next UTC day.
func TestReleaseFreesTheEnvelopeAndTheNextPeriodResets(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0 })
	env := twoCentEnvelope()
	first, ok, err := admitOnce(h, env, "idem-release-1")
	if err != nil || !ok {
		t.Fatalf("first admission: %v %v", ok, err)
	}
	if _, ok, err := admitOnce(h, env, "idem-release-2"); err != nil || !ok {
		t.Fatalf("second admission: %v %v", ok, err)
	}
	if _, ok, _ := admitOnce(h, env, "idem-release-3"); ok {
		t.Fatal("a third cent was admitted against a 2-cent envelope")
	}
	if _, err := h.engine.ReleaseReservation(first.Quote); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, ok, err := admitOnce(h, env, "idem-release-4"); err != nil || !ok {
		t.Fatalf("after a release the freed cent was not admitted: %v %v", ok, err)
	}
	h.advance(24 * time.Hour)
	// The harness prices expire within the hour; price the next day.
	if err := h.prices.Put(buildSnapshot("price-openai-gpt", "openai", "gpt-6-sol", "terms-openai", "sha256:src-openai",
		h.now.Add(24*time.Hour-time.Minute), h.now.Add(25*time.Hour), 500, 1500)); err != nil {
		t.Fatalf("put snapshot: %v", err)
	}
	if _, ok, err := admitOnce(h, env, "idem-next-day"); err != nil || !ok {
		t.Fatalf("a daily envelope did not reset the next day: %v %v", ok, err)
	}
}

// TestRestoredPendingDispatchHoldsTheEnvelope (audit M18): a dispatch a
// previous run journalled and never settled is held again on the balance and
// the envelope, and its key cannot reserve again.
func TestRestoredPendingDispatchHoldsTheEnvelope(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0 })
	env := twoCentEnvelope()
	res, ok, err := admitOnce(h, env, "idem-pending")
	if err != nil || !ok {
		t.Fatalf("admission: %v %v", ok, err)
	}
	// A second engine over a fresh ledger stands for the restarted process.
	h2 := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0 })
	restored, err := h2.engine.RestorePendingDispatch(env, res.Quote, h2.now)
	if err != nil || restored == nil || !restored.Pending {
		t.Fatalf("restore = %+v, %v; want a pending reservation", restored, err)
	}
	if h2.ledger.HoldCents() != res.Quote.MaxAmountCents {
		t.Fatalf("hold = %d, want %d", h2.ledger.HoldCents(), res.Quote.MaxAmountCents)
	}
	again, err := h2.engine.Quote(env, h2.req("idem-pending", "gpt-6-sol", 10, 10))
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	if _, err := h2.engine.ReserveForDispatch(again); !errors.Is(err, ErrDispatchConflict) {
		t.Fatalf("reserve of the pending key = %v, want ErrDispatchConflict", err)
	}
	if consumed := h2.ledger.envelopeConsumed(env, h2.now); consumed != res.Quote.MaxAmountCents {
		t.Fatalf("envelope consumed = %d, want the pending %d reserved", consumed, res.Quote.MaxAmountCents)
	}
}

// TestSettleAtHoldDebitsTheCeiling (audit H8): a dispatch whose usage is not
// known is debited the whole hold, and the receipt says so.
func TestSettleAtHoldDebitsTheCeiling(t *testing.T) {
	h := newHarness(t)
	res, err := h.engine.Quote(h.env, h.req("idem-at-hold", "gpt-6-sol", 1000, 500))
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	if _, err := h.engine.ReserveForDispatch(res); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	settle, err := h.engine.SettleAtHold(res.Quote, "", "the provider's usage was not readable", nil)
	if err != nil {
		t.Fatalf("settle at hold: %v", err)
	}
	if !settle.AtHold || settle.BalanceDebitCents != res.Quote.MaxAmountCents || h.ledger.HoldCents() != 0 {
		t.Fatalf("settle = %+v, hold %d; want the whole %d-cent hold debited", settle, h.ledger.HoldCents(), res.Quote.MaxAmountCents)
	}
	if settle.UsageReceipt.Metadata["settled_at_hold"] == "" || settle.UsageReceipt.InputTokens != 0 {
		t.Fatalf("usage receipt = %+v; want settled_at_hold recorded and no token counts claimed", settle.UsageReceipt)
	}
	if _, err := h.engine.ReserveForDispatch(res); !errors.Is(err, ErrDispatchConflict) {
		t.Fatalf("a key settled at its hold reserved again: %v", err)
	}
}

// TestQuotePrincipalIsTheEnvelopes (audit M17): a quote and its receipt name
// the envelope's principal; a request may not name another.
func TestQuotePrincipalIsTheEnvelopes(t *testing.T) {
	h := newHarness(t)
	req := h.req("idem-principal", "gpt-6-sol", 10, 10)
	req.PrincipalID = "principal-mallory"
	if _, err := h.engine.Quote(h.env, req); err == nil {
		t.Fatal("a request naming another principal than its envelope's was quoted")
	}
	req.PrincipalID = ""
	res, err := h.engine.Quote(h.env, req)
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	if _, err := h.engine.ReserveForDispatch(res); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if res.Quote.PrincipalID != h.env.PrincipalID || res.Receipt.PrincipalID != h.env.PrincipalID {
		t.Fatalf("quote/receipt principal = %q/%q, want the envelope's %q", res.Quote.PrincipalID, res.Receipt.PrincipalID, h.env.PrincipalID)
	}
}

// TestReservationDecidesAgainstWhatOthersReserved: three quotes made before
// any reservation all see an untouched 2-cent envelope; the reservation, which
// decides again in the same step as it reserves, admits only two of them.
func TestReservationDecidesAgainstWhatOthersReserved(t *testing.T) {
	h := newHarness(t, func(c *EngineConfig) { c.PlatformFeeBps = 0 })
	env := twoCentEnvelope()
	var quoted []*QuoteResult
	for i := range 3 {
		res, err := h.engine.Quote(env, h.req(fmt.Sprintf("idem-stale-%d", i), "gpt-6-sol", 10, 10))
		if err != nil {
			t.Fatalf("quote %d: %v", i, err)
		}
		quoted = append(quoted, res)
	}
	admitted := 0
	for _, res := range quoted {
		if _, err := h.engine.ReserveForDispatch(res); err == nil {
			admitted++
		} else if res.Receipt != nil || res.Quote.BudgetVerdict != economic.BudgetVerdictDeny {
			t.Fatalf("a refused reservation left an allowing quote or a receipt: %v", err)
		}
	}
	if admitted != 2 {
		t.Fatalf("%d of three quotes reserved against a 2-cent envelope, want 2", admitted)
	}
}
