package inferencegateway

import (
	"errors"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// ErrDispatchConflict reports that a dispatch for the same quote (and so the
// same idempotency key) already holds a reservation or has settled.
var ErrDispatchConflict = errors.New("inferencegateway: a dispatch for this idempotency key is already in flight or settled")

// ReserveForDispatch places the pre-dispatch hold for an ALLOW'd quote. Every
// dispatch must reserve its estimated max cost before the provider is called.
// The hold is keyed on the quote id, which is derived from the idempotency key,
// and it is exclusive: while one dispatch holds it, or once it has settled, a
// second reservation fails with ErrDispatchConflict. After ReleaseReservation
// a retry may reserve again. The hold is bound to the quote's signed
// budget-verdict receipt hash.
//
// The quote must carry a ReceiptHash (set by Quote on an ALLOW verdict) and be
// unexpired; otherwise it was never authorized for dispatch and is refused.
func (e *Engine) ReserveForDispatch(quote *economic.RouteQuote) (*Reservation, error) {
	if quote == nil {
		return nil, errors.New("inferencegateway: route quote is required to reserve")
	}
	if err := quote.Validate(); err != nil {
		return nil, err
	}
	if quote.BudgetVerdict != economic.BudgetVerdictAllow {
		return nil, errors.New("inferencegateway: cannot reserve against a non-ALLOW quote")
	}
	if quote.ReceiptHash == "" {
		return nil, errors.New("inferencegateway: quote has no budget-verdict receipt hash; not authorized for dispatch")
	}
	if quote.MaxAmountCents <= 0 {
		return nil, errors.New("inferencegateway: quote max amount must be positive to reserve")
	}
	if quote.Expired(e.cfg.Now()) {
		return nil, errors.New("inferencegateway: route quote expired before dispatch")
	}
	return e.cfg.Ledger.reserveExclusive(quote.ID, quote.MaxAmountCents, quote.ReceiptHash)
}

// ReleaseReservation frees the dispatch hold when a run fails before settlement.
// It is idempotent and refuses to release a reservation already consumed by a
// debit (a settled run cannot be "failed").
func (e *Engine) ReleaseReservation(quote *economic.RouteQuote) (*economic.UsageLedgerEntry, error) {
	if quote == nil {
		return nil, errors.New("inferencegateway: route quote is required to release")
	}
	return e.cfg.Ledger.Release(quote.ID)
}
