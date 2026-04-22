package budget_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/budget"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockEnforcer implements Enforcer for testing
type MockEnforcer struct {
	budgets map[string]*budget.Budget
	spends  map[string]int64
}

func NewMockEnforcer() *MockEnforcer {
	return &MockEnforcer{
		budgets: make(map[string]*budget.Budget),
		spends:  make(map[string]int64),
	}
}

func (e *MockEnforcer) SetLimits(ctx context.Context, tenantID string, daily, monthly int64) error {
	e.budgets[tenantID] = &budget.Budget{
		TenantID:     tenantID,
		DailyLimit:   daily,
		MonthlyLimit: monthly,
		LastUpdated:  time.Now().UTC(),
	}
	return nil
}

func (e *MockEnforcer) GetBudget(ctx context.Context, tenantID string) (*budget.Budget, error) {
	b, ok := e.budgets[tenantID]
	if !ok {
		return nil, assert.AnError
	}
	b.DailyUsed = e.spends[tenantID+"_daily"]
	b.MonthlyUsed = e.spends[tenantID+"_monthly"]
	return b, nil
}

func (e *MockEnforcer) Check(ctx context.Context, tenantID string, cost budget.Cost) (*budget.Decision, error) {
	b, err := e.GetBudget(ctx, tenantID)
	if err != nil {
		// FAIL CLOSED
		return &budget.Decision{
			Allowed: false,
			Reason:  "budget check failed",
			Receipt: &budget.EnforcementReceipt{
				TenantID:  tenantID,
				Action:    "denied",
				CostCents: cost.Amount,
				Reason:    "budget_check_failed",
				Timestamp: time.Now().UTC(),
			},
		}, nil
	}

	if b.DailyLimit > 0 && b.DailyUsed+cost.Amount > b.DailyLimit {
		return &budget.Decision{
			Allowed:   false,
			Reason:    "daily budget exceeded",
			Remaining: b,
		}, nil
	}

	if b.MonthlyLimit > 0 && b.MonthlyUsed+cost.Amount > b.MonthlyLimit {
		return &budget.Decision{
			Allowed:   false,
			Reason:    "monthly budget exceeded",
			Remaining: b,
		}, nil
	}

	return &budget.Decision{
		Allowed:   true,
		Reason:    "within budget",
		Remaining: b,
	}, nil
}

func (e *MockEnforcer) RecordSpend(ctx context.Context, tenantID string, cost budget.Cost) error {
	e.spends[tenantID+"_daily"] += cost.Amount
	e.spends[tenantID+"_monthly"] += cost.Amount
	return nil
}

func TestBudget_WithinLimits(t *testing.T) {
	enforcer := NewMockEnforcer()
	ctx := context.Background()

	// Set limits: $100/day, $1000/month
	err := enforcer.SetLimits(ctx, "tenant-1", 10000, 100000)
	require.NoError(t, err)

	// Check $10 cost - should be allowed
	decision, err := enforcer.Check(ctx, "tenant-1", budget.Cost{Amount: 1000})
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "within budget", decision.Reason)
}

func TestBudget_DailyLimitExceeded(t *testing.T) {
	enforcer := NewMockEnforcer()
	ctx := context.Background()

	// Set limits: $10/day
	err := enforcer.SetLimits(ctx, "tenant-2", 1000, 100000)
	require.NoError(t, err)

	// Spend $8
	err = enforcer.RecordSpend(ctx, "tenant-2", budget.Cost{Amount: 800})
	require.NoError(t, err)

	// Try to spend $5 more - should be denied
	decision, err := enforcer.Check(ctx, "tenant-2", budget.Cost{Amount: 500})
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "daily")
}

func TestBudget_FailClosed(t *testing.T) {
	enforcer := NewMockEnforcer()
	ctx := context.Background()

	// Don't set any budget for tenant - should fail closed
	decision, err := enforcer.Check(ctx, "unknown-tenant", budget.Cost{Amount: 100})
	require.NoError(t, err) // No error, but decision is denied
	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "failed")
	assert.NotNil(t, decision.Receipt)
	assert.Equal(t, "denied", decision.Receipt.Action)
}

func TestBudget_Remaining(t *testing.T) {
	b := &budget.Budget{
		DailyLimit:   10000,
		MonthlyLimit: 100000,
		DailyUsed:    7500,
		MonthlyUsed:  25000,
	}

	assert.Equal(t, int64(2500), b.DailyRemaining())
	assert.Equal(t, int64(75000), b.MonthlyRemaining())
}

func TestBudget_RemainingNegative(t *testing.T) {
	b := &budget.Budget{
		DailyLimit: 10000,
		DailyUsed:  15000, // Overdrawn
	}

	assert.Equal(t, int64(0), b.DailyRemaining())
}
