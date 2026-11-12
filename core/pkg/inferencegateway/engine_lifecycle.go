package inferencegateway

import (
	"errors"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// ErrDispatchConflict reports that a dispatch for the same quote (and so the
// same idempotency key) already holds a reservation or has settled.
var ErrDispatchConflict = errors.New("inferencegateway: a dispatch for this idempotency key is already in flight or settled")

// ReserveForDispatch admits an ALLOW'd quote for dispatch. In one step under
// the ledger lock it decides the quote again against what its envelope has
// left in the current period, and on an allowing decision reserves the quote's
// ceiling against the envelope and the balance together: concurrent dispatches
// cannot both take the last cents (helm-tracker#313, audit H7). Only then is
// the budget-verdict receipt issued: res.Receipt is set, the quote is bound to
// the receipt's hash and resealed, and res.Decision is the decision the
// reservation was made on.
//
// The hold is keyed on the quote id, which is derived from the idempotency key,
// and it is exclusive: while one dispatch holds it, or once it has settled, a
// second reservation fails with ErrDispatchConflict and leaves res as it was.
// After ReleaseReservation a retry may reserve again.
//
// When the envelope or the balance cannot cover the quote, the reservation is
// refused with a *QuoteError and res is rewritten to the refusal: its quote
// carries the DENY verdict and no receipt hash, and it has no receipt.
//
// res must come from this engine's Quote with an ALLOW verdict and an
// unexpired quote; otherwise it was never authorized for dispatch.
func (e *Engine) ReserveForDispatch(res *QuoteResult) (*Reservation, error) {
	if res == nil || res.Quote == nil {
		return nil, errors.New("inferencegateway: a quote result is required to reserve")
	}
	if res.env == nil || res.PriceSnapshot == nil {
		return nil, errors.New("inferencegateway: the quote result did not come from Quote; not authorized for dispatch")
	}
	quote := res.Quote
	if err := quote.Validate(); err != nil {
		return nil, err
	}
	if quote.BudgetVerdict != economic.BudgetVerdictAllow {
		return nil, errors.New("inferencegateway: cannot reserve against a non-ALLOW quote")
	}
	if quote.RoutePolicyHash != e.routePolicyHash || quote.EnvelopeID != res.env.ID {
		return nil, errors.New("inferencegateway: the quote was not issued by this engine for its envelope")
	}
	if quote.MaxAmountCents <= 0 {
		return nil, errors.New("inferencegateway: quote max amount must be positive to reserve")
	}
	now := e.cfg.Now()
	if quote.Expired(now) {
		return nil, errors.New("inferencegateway: route quote expired before dispatch")
	}

	var decision economic.SpendAuthorityDecision
	var receipt *economic.BudgetVerdictReceipt
	reservation, err := e.cfg.Ledger.reserveDispatch(quote.ID, res.env, quote.MaxAmountCents, now, func(state envelopeSpend) (string, error) {
		decision = decideSpend(res.env, state, quote.MaxAmountCents, quote.SelectedProviderID, quote.SelectedModelID)
		if decision.Verdict != economic.BudgetVerdictAllow {
			return "", quoteErr(decision.Verdict, decision.ReasonCode, decision.Reason)
		}
		receipt = e.issueReceipt(res, decision)
		return receipt.ContentHash, nil
	})
	switch {
	case errors.Is(err, ErrDispatchConflict):
		return nil, err
	case err != nil:
		var qe *QuoteError
		if !errors.As(err, &qe) {
			// The balance could not hold the quote; the envelope could.
			qe = quoteErr(economic.BudgetVerdictDeny, economic.SpendReasonBalanceInsufficient, err.Error())
			decision = refusal(qe, decision.RemainingCents, res.env.ContentHash)
		}
		res.deny(decision)
		return nil, qe
	}
	quote.ReceiptHash = receipt.ContentHash
	quote.Reseal()
	res.Receipt = receipt
	res.Decision = decision
	return reservation, nil
}

// refusal is the decision record of a refusal the envelope did not make.
func refusal(qe *QuoteError, remainingCents int64, envelopeHash string) economic.SpendAuthorityDecision {
	d := economic.SpendAuthorityDecision{Verdict: qe.Verdict, ReasonCode: qe.ReasonCode, Reason: qe.Message,
		RemainingCents: remainingCents, EnvelopeHash: envelopeHash}
	d.ContentHash = d.CanonicalContentHash()
	return d
}

// ReleaseReservation frees the dispatch hold, on the balance and on the
// envelope, when the provider was provably never called: an error before any
// request byte left the process. A dispatch that may have reached the provider
// settles instead (Settle, SettleAtHold), or keeps its hold. Release is
// idempotent and refuses to release a reservation already consumed by a debit
// (a settled run cannot be "failed").
func (e *Engine) ReleaseReservation(quote *economic.RouteQuote) (*economic.UsageLedgerEntry, error) {
	if quote == nil {
		return nil, errors.New("inferencegateway: route quote is required to release")
	}
	return e.cfg.Ledger.Release(quote.ID)
}

// RestorePendingDispatch re-places, after a restart, the hold of a dispatch a
// previous run journalled before its provider call and never settled or
// released (audit M18). The provider may have billed it, so the quote's ceiling
// stays reserved against env and the balance, pending reconciliation, and its
// idempotency key cannot dispatch again. at is when it was journalled, which
// names the envelope window. holdCents is the hold placed, at least the
// quote's MaxAmountCents: more when the log records that the provider billed
// more (helm-tracker#313 r3, finding 1). A key already settled or already held
// is left as it is.
func (e *Engine) RestorePendingDispatch(env *economic.AgentSpendEnvelope, quote *economic.RouteQuote, at time.Time, holdCents int64) (*Reservation, error) {
	if env == nil || quote == nil {
		return nil, errors.New("inferencegateway: an envelope and a quote are required to restore a pending dispatch")
	}
	if err := quote.Validate(); err != nil {
		return nil, err
	}
	if quote.EnvelopeID != env.ID || quote.TenantID != env.TenantID {
		return nil, errors.New("inferencegateway: the pending dispatch does not belong to this envelope")
	}
	if _, settled := e.cfg.Ledger.Lookup(idempotencyFromIntent(quote.SpendIntentID)); settled {
		return nil, nil
	}
	bound := quote.ReceiptHash
	if bound == "" {
		bound = quote.ContentHash
	}
	return e.cfg.Ledger.restorePending(quote.ID, env, max(holdCents, quote.MaxAmountCents), bound, at)
}
