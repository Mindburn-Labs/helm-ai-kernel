// Package budget provides per-tenant budget enforcement with fail-closed behavior.
// When budget checks fail or are uncertain, access is denied to prevent cost overruns.
package budget

import (
	"context"
	"time"
)

// Cost represents a cost estimate for an operation.
type Cost struct {
	Amount   int64  // In cents
	Currency string // e.g., "USD"
	Reason   string // What the cost is for
}

// Budget represents a tenant's budget limits and current usage.
type Budget struct {
	TenantID     string    `json:"tenant_id"`
	DailyLimit   int64     `json:"daily_limit"`   // cents
	MonthlyLimit int64     `json:"monthly_limit"` // cents
	DailyUsed    int64     `json:"daily_used"`    // cents
	MonthlyUsed  int64     `json:"monthly_used"`  // cents
	LastUpdated  time.Time `json:"last_updated"`
}

// Remaining returns how much budget is remaining for the day.
func (b *Budget) DailyRemaining() int64 {
	remaining := b.DailyLimit - b.DailyUsed
	if remaining < 0 {
		return 0
	}
	return remaining
}

// MonthlyRemaining returns how much budget is remaining for the month.
func (b *Budget) MonthlyRemaining() int64 {
	remaining := b.MonthlyLimit - b.MonthlyUsed
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Decision represents the result of a budget check.
type Decision struct {
	Allowed   bool                `json:"allowed"`
	Reason    string              `json:"reason"`
	Remaining *Budget             `json:"remaining,omitempty"`
	Receipt   *EnforcementReceipt `json:"receipt,omitempty"`
}

// EnforcementReceipt provides evidence of budget enforcement.
type EnforcementReceipt struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Action    string    `json:"action"` // "allowed" or "denied"
	CostCents int64     `json:"cost_cents"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// Enforcer is the interface for budget enforcement.
type Enforcer interface {
	// Check verifies if a cost can be incurred. Fails closed on errors.
	Check(ctx context.Context, tenantID string, cost Cost) (*Decision, error)

	// GetBudget retrieves current budget status for a tenant.
	GetBudget(ctx context.Context, tenantID string) (*Budget, error)

	// SetLimits updates the budget limits for a tenant.
	SetLimits(ctx context.Context, tenantID string, daily, monthly int64) error

	// RecordSpend records actual spend after operation completes.
	RecordSpend(ctx context.Context, tenantID string, cost Cost) error
}
