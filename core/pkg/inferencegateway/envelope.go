package inferencegateway

import (
	"fmt"
	"math"
	"slices"
	"strings"
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
// A settlement above its reservation (a provider that billed more than the
// hold the quote bounded) closes the reservation's window and the window the
// settlement falls in, which differ when a dispatch straddles a period
// boundary: the envelope takes no further dispatch in either, so it passes its
// limit by at most the overages of the dispatches already in flight when the
// first one settled. The usage receipt names the window its debit is booked
// in and the windows it closed (MetadataEnvelopeWindow,
// MetadataEnvelopeClosedWindows), so a restart rebuilds the same state.

// The usage-receipt metadata keys that record an envelope's windows.
const (
	// MetadataEnvelopeWindow is the period window a settlement's debit is
	// booked in: its reservation's, or the window that contains the
	// settlement time when no reservation backs it.
	MetadataEnvelopeWindow = "envelope_window"
	// MetadataEnvelopeClosed is the envelope a debit above its reservation
	// closed, and MetadataEnvelopeClosedWindows the windows it closed,
	// comma-separated in order.
	MetadataEnvelopeClosed        = "envelope_closed"
	MetadataEnvelopeClosedWindows = "envelope_closed_windows"
)

// envelopeWindow names one period of one envelope.
type envelopeWindow struct {
	envelopeID string
	window     string
}

// envelopeSpend is what one envelope window has reserved and used, in cents,
// and whether a settlement above its hold closed it.
type envelopeSpend struct {
	reserved int64
	used     int64
	closed   bool
}

// PeriodWindow names the window of period p that contains t, as a usage
// receipt's MetadataEnvelopeWindow does.
func PeriodWindow(p economic.SpendPeriod, t time.Time) string { return periodWindow(p, t) }

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

// errEnvelopeClosed is the refusal of an envelope window a settlement above
// its hold closed.
var errEnvelopeClosed = quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonEnvelopeInactive,
	"the spend envelope is closed for this period: a provider billed a dispatch above its hold")

// decideSpend is the verdict on amountCents against env as it stands in a
// window: what its requests reserved and used, and whether it is closed.
func decideSpend(env *economic.AgentSpendEnvelope, state envelopeSpend, amountCents int64, providerID, modelID string) economic.SpendAuthorityDecision {
	effective := effectiveEnvelope(env, addSaturating(state.reserved, state.used))
	if state.closed {
		return refusal(errEnvelopeClosed, effective.RemainingCents(), env.ContentHash)
	}
	return effective.EvaluateSpend(amountCents, providerID, modelID)
}

func addSaturating(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// envelopeWindowLocked registers env and returns its window at now. Callers
// must hold l.mu.
func (l *BalanceLedger) envelopeWindowLocked(env *economic.AgentSpendEnvelope, now time.Time) envelopeWindow {
	l.envelopes[env.ID] = env
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

// envelopeState is what env's requests have reserved and used in the window
// that contains now, and whether it is closed.
func (l *BalanceLedger) envelopeState(env *economic.AgentSpendEnvelope, now time.Time) envelopeSpend {
	l.mu.Lock()
	defer l.mu.Unlock()
	return *l.envelopeSpendLocked(l.envelopeWindowLocked(env, now))
}

// RestoreEnvelopeUse re-applies what a previous process run recorded for env,
// so a restarted engine does not hand the same limit out again: cents used in
// window (the usage receipt's MetadataEnvelopeWindow; empty for a receipt
// written before it existed, which books in the window that contains at), and
// the windows a settlement above its hold closed, which close again. Call it
// beside RestoreSettlement, and with no cents for a closure whose debit failed.
func (l *BalanceLedger) RestoreEnvelopeUse(env *economic.AgentSpendEnvelope, at time.Time, window string, cents int64, closedWindows []string) {
	if env == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.envelopeWindowLocked(env, at)
	if window != "" {
		w.window = window
	}
	if cents > 0 {
		s := l.envelopeSpendLocked(w)
		s.used = addSaturating(s.used, cents)
	}
	for _, closed := range closedWindows {
		if closed != "" {
			l.envelopeSpendLocked(envelopeWindow{envelopeID: env.ID, window: closed}).closed = true
		}
	}
}

// reserveDispatch is admission's one step: under the ledger lock it refuses a
// key that already holds or has settled, asks issue to decide against what the
// envelope has left in its window, and on an allowing decision places the
// balance hold and the envelope reservation together. issue returns the hash
// the hold is bound to (the budget-verdict receipt it issued).
func (l *BalanceLedger) reserveDispatch(key string, env *economic.AgentSpendEnvelope, amountCents int64, now time.Time, issue func(state envelopeSpend) (string, error)) (*Reservation, error) {
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
	receiptHash, err := issue(*spend)
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

// retainActualHoldLocked keeps a provider's known bill reserved when settlement
// cannot debit it. Otherwise another envelope could spend the unfunded bill's
// remaining balance before a restart restores it. Callers must hold l.mu.
func (l *BalanceLedger) retainActualHoldLocked(res *Reservation, actual int64, now time.Time) error {
	if res == nil || actual <= res.AmountCents {
		return nil
	}
	extra := actual - res.AmountCents
	entry := economic.NewUsageLedgerEntry(l.nextEntryIDLocked("reserve"), l.account.TenantID, l.account.ID,
		economic.UsageLedgerReserve, economic.SettlementDebit, extra, l.account.Currency,
		economic.SpendReasonSettlementMissing, res.ReceiptHash)
	if err := entry.Validate(); err != nil {
		return err
	}
	l.account.HoldCents += extra
	l.account.UpdatedAt = now.UTC()
	res.AmountCents = actual
	res.Pending = true
	if res.EnvelopeID != "" {
		spend := l.envelopeSpendLocked(envelopeWindow{envelopeID: res.EnvelopeID, window: res.EnvelopeWindow})
		spend.reserved = addSaturating(spend.reserved, extra)
	}
	l.entries = append(l.entries, entry)
	return nil
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
// reservation's window when there is one (its reserved cents become used; a
// debit above them closed the window, closeAboveHoldLocked), the current
// window of the usage's envelope otherwise. Callers must hold l.mu.
func (l *BalanceLedger) settleEnvelopeLocked(res *Reservation, envelopeID string, debitCents int64, now time.Time) {
	if res != nil && res.EnvelopeID != "" {
		spend := l.envelopeSpendLocked(envelopeWindow{envelopeID: res.EnvelopeID, window: res.EnvelopeWindow})
		spend.reserved = max(0, spend.reserved-res.AmountCents)
		spend.used = addSaturating(spend.used, debitCents)
		return
	}
	if w, ok := l.unreservedWindowLocked(envelopeID, now); ok {
		spend := l.envelopeSpendLocked(w)
		spend.used = addSaturating(spend.used, debitCents)
	}
}

// closeAboveHoldLocked closes, for a reservation whose debit goes above it,
// the reservation's window and the window that contains now, even when the
// debit then fails: the bound the hold rested on did not hold. It returns the
// windows it closed, in order, or none for a debit within its reservation.
// Callers must hold l.mu.
func (l *BalanceLedger) closeAboveHoldLocked(res *Reservation, debitCents int64, now time.Time) []string {
	if res == nil || res.EnvelopeID == "" || debitCents <= res.AmountCents {
		return nil
	}
	windows := []string{res.EnvelopeWindow}
	if env := l.envelopes[res.EnvelopeID]; env != nil {
		if current := periodWindow(env.Period, now); current != res.EnvelopeWindow {
			windows = append(windows, current)
		}
	}
	slices.Sort(windows)
	for _, w := range windows {
		l.envelopeSpendLocked(envelopeWindow{envelopeID: res.EnvelopeID, window: w}).closed = true
	}
	return windows
}

// recordEnvelopeWindows writes on a usage receipt the window its debit is
// booked in and the envelope windows it closed. Metadata is not part of the
// receipt's content hash; the receipt is not yet shared. Callers must hold
// l.mu.
func recordEnvelopeWindows(usage *economic.UsageReceipt, envelopeID, window string, closed []string) {
	if window == "" && len(closed) == 0 {
		return
	}
	if usage.Metadata == nil {
		usage.Metadata = map[string]string{}
	}
	if window != "" {
		usage.Metadata[MetadataEnvelopeWindow] = window
	}
	if len(closed) > 0 {
		usage.Metadata[MetadataEnvelopeClosed] = envelopeID
		usage.Metadata[MetadataEnvelopeClosedWindows] = strings.Join(closed, ",")
	}
}

// envelopeClosure reads back what recordEnvelopeWindows recorded as closed.
func envelopeClosure(usage *economic.UsageReceipt) (string, []string) {
	if usage == nil || usage.Metadata[MetadataEnvelopeClosed] == "" {
		return "", nil
	}
	return usage.Metadata[MetadataEnvelopeClosed], strings.Split(usage.Metadata[MetadataEnvelopeClosedWindows], ",")
}

// unreservedWindowLocked is the window a debit without a reservation is booked
// in: the current window of its envelope, as this ledger evaluated it.
// Callers must hold l.mu.
func (l *BalanceLedger) unreservedWindowLocked(envelopeID string, now time.Time) (envelopeWindow, bool) {
	env := l.envelopes[envelopeID]
	if env == nil {
		return envelopeWindow{}, false
	}
	return envelopeWindow{envelopeID: envelopeID, window: periodWindow(env.Period, now)}, true
}
