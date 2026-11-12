package inferencegateway

import (
	"fmt"
	"math"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// An AgentSpendEnvelope is configuration: its content hash seals its limit,
// and its own used and reserved fields are what it was issued with. What its
// requests spend is the ledger's: each envelope has, per period window, the
// cents its open dispatch holds reserve and the cents its settlements used
// (helm-tracker#313). A reservation is checked and placed in one critical
// section of the ledger, so two concurrent dispatches cannot both take the
// last cents; a settlement moves its reservation to used; a release frees it.

// envelopeWindow names one period of one envelope.
type envelopeWindow struct {
	envelopeID string
	window     string
}

// envelopeSpend is what one envelope window has reserved and used, in cents.
type envelopeSpend struct {
	reserved int64
	used     int64
}

// periodWindow is the period of p that contains t, in UTC: a day, an ISO
// week, a month or a quarter. A period the engine does not know is one window
// for the envelope's whole life, which never resets and so never allows more.
func periodWindow(p economic.SpendPeriod, t time.Time) string {
	t = t.UTC()
	switch p {
	case economic.SpendPeriodDaily:
		return t.Format("2006-01-02")
	case economic.SpendPeriodWeekly:
		year, week := t.ISOWeek()
		return fmt.Sprintf("%04d-W%02d", year, week)
	case economic.SpendPeriodMonthly:
		return t.Format("2006-01")
	case economic.SpendPeriodQuarterly:
		return fmt.Sprintf("%04d-Q%d", t.Year(), (int(t.Month())-1)/3+1)
	default:
		return "lifetime"
	}
}

// effectiveEnvelope is env with consumedCents more used, for evaluation only:
// its RemainingCents is what the envelope can still pay in this window, and
// its ContentHash stays the configured envelope's.
func effectiveEnvelope(env *economic.AgentSpendEnvelope, consumedCents int64) *economic.AgentSpendEnvelope {
	eff := *env
	eff.UsedAmountCents = addSaturating(env.UsedAmountCents, consumedCents)
	return &eff
}

func addSaturating(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// envelopeWindowLocked registers env's period and returns its window at now.
// Callers must hold l.mu.
func (l *BalanceLedger) envelopeWindowLocked(env *economic.AgentSpendEnvelope, now time.Time) envelopeWindow {
	l.envelopePeriods[env.ID] = env.Period
	return envelopeWindow{envelopeID: env.ID, window: periodWindow(env.Period, now)}
}

// envelopeSpendLocked returns the window's account, creating it. Callers must
// hold l.mu.
func (l *BalanceLedger) envelopeSpendLocked(w envelopeWindow) *envelopeSpend {
	s := l.envelopeSpend[w]
	if s == nil {
		s = &envelopeSpend{}
		l.envelopeSpend[w] = s
	}
	return s
}

// envelopeConsumed is what env's requests have reserved and used in the window
// that contains now.
func (l *BalanceLedger) envelopeConsumed(env *economic.AgentSpendEnvelope, now time.Time) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.envelopeSpendLocked(l.envelopeWindowLocked(env, now))
	return addSaturating(s.reserved, s.used)
}

// RestoreEnvelopeUse re-applies a settlement committed in a previous process
// run to its envelope's window, so a restarted engine does not hand the same
// limit out again. Call it beside RestoreSettlement.
func (l *BalanceLedger) RestoreEnvelopeUse(env *economic.AgentSpendEnvelope, at time.Time, cents int64) {
	if env == nil || cents <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.envelopeSpendLocked(l.envelopeWindowLocked(env, at))
	s.used = addSaturating(s.used, cents)
}

// reserveDispatch is admission's one step: under the ledger lock it refuses a
// key that already holds or has settled, asks issue to decide against what the
// envelope has left in its window, and on an allowing decision places the
// balance hold and the envelope reservation together. issue returns the hash
// the hold is bound to (the budget-verdict receipt it issued).
func (l *BalanceLedger) reserveDispatch(key string, env *economic.AgentSpendEnvelope, amountCents int64, now time.Time, issue func(consumedCents int64) (string, error)) (*Reservation, error) {
	if key == "" || amountCents <= 0 || env == nil {
		return nil, fmt.Errorf("inferencegateway: a dispatch reservation needs a key, a positive amount and an envelope")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, ok := l.reservations[key]; ok && !existing.Released {
		return nil, ErrDispatchConflict
	}
	window := l.envelopeWindowLocked(env, now)
	spend := l.envelopeSpendLocked(window)
	receiptHash, err := issue(addSaturating(spend.reserved, spend.used))
	if err != nil {
		return nil, err
	}
	res, err := l.reserveLocked(key, amountCents, receiptHash, false)
	if err != nil {
		return nil, err
	}
	res.EnvelopeID, res.EnvelopeWindow = window.envelopeID, window.window
	spend.reserved = addSaturating(spend.reserved, amountCents)
	return res, nil
}

// restorePending re-places the hold of a dispatch a previous process run
// journalled and never settled: the provider may have billed it, so its cents
// stay reserved against the balance and the envelope, pending reconciliation,
// and its key cannot reserve again. The hold is placed even when the balance
// no longer covers it, for the same reason.
func (l *BalanceLedger) restorePending(key string, env *economic.AgentSpendEnvelope, amountCents int64, boundHash string, at time.Time) (*Reservation, error) {
	if key == "" || amountCents <= 0 || env == nil || boundHash == "" {
		return nil, fmt.Errorf("inferencegateway: a pending dispatch needs a key, a positive amount, an envelope and a bound hash")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, ok := l.reservations[key]; ok && !existing.Released {
		return existing, nil
	}
	res, err := l.reserveLocked(key, amountCents, boundHash, true)
	if err != nil {
		return nil, err
	}
	window := l.envelopeWindowLocked(env, at)
	res.EnvelopeID, res.EnvelopeWindow = window.envelopeID, window.window
	res.Pending = true
	spend := l.envelopeSpendLocked(window)
	spend.reserved = addSaturating(spend.reserved, amountCents)
	return res, nil
}

// releaseEnvelopeLocked frees a reservation's envelope cents. Callers must
// hold l.mu.
func (l *BalanceLedger) releaseEnvelopeLocked(res *Reservation) {
	if res == nil || res.EnvelopeID == "" {
		return
	}
	spend := l.envelopeSpendLocked(envelopeWindow{envelopeID: res.EnvelopeID, window: res.EnvelopeWindow})
	spend.reserved = max(0, spend.reserved-res.AmountCents)
}

// settleEnvelopeLocked books a debit on the envelope that authorized it: the
// reservation's window when there is one (its reserved cents become used), the
// current window of the usage's envelope otherwise. Callers must hold l.mu.
func (l *BalanceLedger) settleEnvelopeLocked(res *Reservation, envelopeID string, debitCents int64, now time.Time) {
	if res != nil && res.EnvelopeID != "" {
		spend := l.envelopeSpendLocked(envelopeWindow{envelopeID: res.EnvelopeID, window: res.EnvelopeWindow})
		spend.reserved = max(0, spend.reserved-res.AmountCents)
		spend.used = addSaturating(spend.used, debitCents)
		return
	}
	if envelopeID == "" {
		return
	}
	period, ok := l.envelopePeriods[envelopeID]
	if !ok {
		period = "" // never evaluated here: one lifetime window
	}
	spend := l.envelopeSpendLocked(envelopeWindow{envelopeID: envelopeID, window: periodWindow(period, now)})
	spend.used = addSaturating(spend.used, debitCents)
}
