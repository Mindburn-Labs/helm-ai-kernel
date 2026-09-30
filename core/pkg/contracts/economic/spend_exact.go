package economic

import (
	"errors"
	"math"
)

// NanoCentsPerCent is the exact accounting scale. Reservation ceilings are not
// provider charges. Convert only at an explicit legacy boundary.
const NanoCentsPerCent int64 = 1_000_000_000

func CentsToNanoCents(cents int64) (int64, error) {
	if cents < 0 || cents > math.MaxInt64/NanoCentsPerCent {
		return 0, errors.New("exact spend: cent conversion out of range")
	}
	return cents * NanoCentsPerCent, nil
}

// ExactSpendBalance is the value portion of an existing account or budget.
// The owning ledger must lock and update its row in the same transaction as
// the hold, receipt and double-entry movements. This type holds no authority.
type ExactSpendBalance struct {
	LimitNanoCents    int64 `json:"limit_nano_cents"`
	ConsumedNanoCents int64 `json:"consumed_nano_cents"`
	ReservedNanoCents int64 `json:"reserved_nano_cents"`
}

func (b ExactSpendBalance) Validate() error {
	if b.LimitNanoCents < 0 || b.ConsumedNanoCents < 0 || b.ReservedNanoCents < 0 ||
		b.ConsumedNanoCents > b.LimitNanoCents || b.ReservedNanoCents > b.LimitNanoCents-b.ConsumedNanoCents {
		return errors.New("exact spend: invalid balance")
	}
	return nil
}

func (b ExactSpendBalance) Reserve(amount int64) (ExactSpendBalance, error) {
	if err := b.Validate(); err != nil {
		return b, err
	}
	if amount <= 0 || amount > b.LimitNanoCents-b.ConsumedNanoCents-b.ReservedNanoCents {
		return b, errors.New("exact spend: reservation exceeds available balance")
	}
	b.ReservedNanoCents += amount
	return b, nil
}

// Settle releases exactly the selected reservation and accrues the observed
// tariff estimate. Zero usage is valid. Unknown usage must not call Settle;
// overage leaves the original balance unchanged for explicit reconciliation.
func (b ExactSpendBalance) Settle(reserved, actual int64) (ExactSpendBalance, error) {
	if err := b.Validate(); err != nil {
		return b, err
	}
	if reserved <= 0 || reserved > b.ReservedNanoCents || actual < 0 || actual > reserved {
		return b, errors.New("exact spend: settlement is outside its reservation")
	}
	b.ReservedNanoCents -= reserved
	b.ConsumedNanoCents += actual // bounded by the released reservation
	return b, nil
}
