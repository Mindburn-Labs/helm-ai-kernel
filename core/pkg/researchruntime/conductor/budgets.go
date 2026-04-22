package conductor

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
)

// BudgetChecker wraps the guardian.BudgetGate interface and exposes a single
// Allow method tuned for conductor use: it checks that the budget has capacity
// and immediately records consumption so concurrent missions cannot race past
// the limit.
type BudgetChecker struct {
	gate     guardian.BudgetGate
	budgetID string
}

// NewBudgetChecker creates a BudgetChecker bound to the given budget ledger ID.
// gate may be nil — in that case every call to Allow succeeds (budget enforcement
// is optional at this layer).
func NewBudgetChecker(gate guardian.BudgetGate, budgetID string) *BudgetChecker {
	return &BudgetChecker{gate: gate, budgetID: budgetID}
}

// Allow checks whether the budget can absorb one more request and, if so,
// records the consumption.  Returns an error if the budget is exhausted.
func (b *BudgetChecker) Allow() error {
	if b.gate == nil {
		return nil
	}
	cost := guardian.BudgetCost{Requests: 1}
	ok, err := b.gate.Check(b.budgetID, cost)
	if err != nil {
		return fmt.Errorf("budget check: %w", err)
	}
	if !ok {
		return fmt.Errorf("budget exhausted for %s", b.budgetID)
	}
	return b.gate.Consume(b.budgetID, cost)
}
