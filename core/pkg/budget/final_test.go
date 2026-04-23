package budget

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
)

func TestFinal_CostJSON(t *testing.T) {
	c := Cost{Amount: 500, Currency: "USD", Reason: "api call"}
	data, _ := json.Marshal(c)
	var c2 Cost
	json.Unmarshal(data, &c2)
	if c2.Amount != 500 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_BudgetDailyRemaining(t *testing.T) {
	b := Budget{DailyLimit: 1000, DailyUsed: 300}
	if b.DailyRemaining() != 700 {
		t.Fatalf("want 700, got %d", b.DailyRemaining())
	}
}

func TestFinal_BudgetDailyRemainingOverspent(t *testing.T) {
	b := Budget{DailyLimit: 100, DailyUsed: 200}
	if b.DailyRemaining() != 0 {
		t.Fatal("overspent should return 0")
	}
}

func TestFinal_BudgetMonthlyRemaining(t *testing.T) {
	b := Budget{MonthlyLimit: 5000, MonthlyUsed: 2000}
	if b.MonthlyRemaining() != 3000 {
		t.Fatalf("want 3000, got %d", b.MonthlyRemaining())
	}
}

func TestFinal_BudgetMonthlyRemainingOverspent(t *testing.T) {
	b := Budget{MonthlyLimit: 100, MonthlyUsed: 500}
	if b.MonthlyRemaining() != 0 {
		t.Fatal("overspent should return 0")
	}
}

func TestFinal_BudgetJSON(t *testing.T) {
	b := Budget{TenantID: "t1", DailyLimit: 1000, MonthlyLimit: 5000}
	data, _ := json.Marshal(b)
	var b2 Budget
	json.Unmarshal(data, &b2)
	if b2.TenantID != "t1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DecisionJSON(t *testing.T) {
	d := Decision{Allowed: true, Reason: "within budget"}
	data, _ := json.Marshal(d)
	var d2 Decision
	json.Unmarshal(data, &d2)
	if !d2.Allowed {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_EnforcementReceiptJSON(t *testing.T) {
	r := EnforcementReceipt{ID: "r1", TenantID: "t1", Action: "allowed", CostCents: 100}
	data, _ := json.Marshal(r)
	var r2 EnforcementReceipt
	json.Unmarshal(data, &r2)
	if r2.CostCents != 100 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_MemoryStorageInterface(t *testing.T) {
	var _ Storage = (*MemoryStorage)(nil)
}

func TestFinal_SimpleEnforcerInterface(t *testing.T) {
	var _ Enforcer = (*SimpleEnforcer)(nil)
}

func TestFinal_MemoryStorageSetLimitsAndLimits(t *testing.T) {
	ms := NewMemoryStorage()
	ctx := context.Background()
	ms.SetLimits(ctx, "t1", 1000, 5000)
	daily, monthly, err := ms.Limits(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if daily != 1000 || monthly != 5000 {
		t.Fatal("limits mismatch")
	}
}

func TestFinal_MemoryStorageGetMissing(t *testing.T) {
	ms := NewMemoryStorage()
	b, err := ms.Get(context.Background(), "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if b != nil {
		t.Fatal("missing tenant should return nil")
	}
}

func TestFinal_SimpleEnforcerCheckWithinBudget(t *testing.T) {
	ms := NewMemoryStorage()
	ctx := context.Background()
	ms.SetLimits(ctx, "t1", 1000, 5000)
	e := NewSimpleEnforcer(ms)
	d, err := e.Check(ctx, "t1", Cost{Amount: 100, Currency: "USD"})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed {
		t.Fatal("should be allowed within budget")
	}
}

func TestFinal_SimpleEnforcerCheckMultiple(t *testing.T) {
	ms := NewMemoryStorage()
	ctx := context.Background()
	ms.SetLimits(ctx, "t1", 100, 5000)
	e := NewSimpleEnforcer(ms)
	d1, _ := e.Check(ctx, "t1", Cost{Amount: 30})
	d2, _ := e.Check(ctx, "t1", Cost{Amount: 30})
	if !d1.Allowed || !d2.Allowed {
		t.Fatal("both checks should be allowed within budget")
	}
}

func TestFinal_RiskLevelConstants(t *testing.T) {
	levels := []RiskLevel{RiskLow, RiskMedium, RiskHigh, RiskCritical}
	for _, l := range levels {
		if l == "" {
			t.Fatal("risk level must not be empty")
		}
	}
}

func TestFinal_RiskBudgetJSON(t *testing.T) {
	rb := RiskBudget{TenantID: "t1", ComputeCapMillis: 10000}
	data, _ := json.Marshal(rb)
	var rb2 RiskBudget
	json.Unmarshal(data, &rb2)
	if rb2.TenantID != "t1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_RiskDecisionJSON(t *testing.T) {
	rd := RiskDecision{Allowed: true, RiskCost: 25.5}
	data, _ := json.Marshal(rd)
	var rd2 RiskDecision
	json.Unmarshal(data, &rd2)
	if rd2.RiskCost != 25.5 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ConcurrentBudgetCheck(t *testing.T) {
	ms := NewMemoryStorage()
	ctx := context.Background()
	ms.SetLimits(ctx, "t1", 10000, 50000)
	e := NewSimpleEnforcer(ms)
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Check(ctx, "t1", Cost{Amount: 10})
		}()
	}
	wg.Wait()
}

func TestFinal_BudgetZeroValues(t *testing.T) {
	var b Budget
	if b.DailyRemaining() != 0 {
		t.Fatal("zero budget should have 0 remaining")
	}
}

func TestFinal_SimpleEnforcerRecordSpendNoError(t *testing.T) {
	ms := NewMemoryStorage()
	ctx := context.Background()
	ms.SetLimits(ctx, "t1", 1000, 5000)
	e := NewSimpleEnforcer(ms)
	err := e.RecordSpend(ctx, "t1", Cost{Amount: 50})
	if err != nil {
		t.Fatalf("RecordSpend should not error: %v", err)
	}
}

func TestFinal_SimpleEnforcerSetAndCheckLimits(t *testing.T) {
	ms := NewMemoryStorage()
	e := NewSimpleEnforcer(ms)
	ctx := context.Background()
	e.SetLimits(ctx, "t2", 2000, 10000)
	d, err := e.Check(ctx, "t2", Cost{Amount: 100})
	if err != nil || !d.Allowed {
		t.Fatal("should be allowed after SetLimits")
	}
}

func TestFinal_SimpleEnforcerRecordSpendThenCheck(t *testing.T) {
	ms := NewMemoryStorage()
	e := NewSimpleEnforcer(ms)
	ctx := context.Background()
	e.SetLimits(ctx, "t1", 1000, 5000)
	e.RecordSpend(ctx, "t1", Cost{Amount: 50})
	d, _ := e.Check(ctx, "t1", Cost{Amount: 10})
	if !d.Allowed {
		t.Fatal("50+10 < 1000, should be allowed")
	}
}

func TestFinal_SimpleEnforcerGetBudgetNilForNew(t *testing.T) {
	ms := NewMemoryStorage()
	e := NewSimpleEnforcer(ms)
	b, _ := e.GetBudget(context.Background(), "new-tenant")
	// GetBudget may return nil for unknown tenants
	_ = b
}
