package budget

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────────────
// 200 concurrent budget checks
// ────────────────────────────────────────────────────────────────────────

func TestStress_200ConcurrentBudgetChecks(t *testing.T) {
	store := NewMemoryStorage()
	_ = store.SetLimits(context.Background(), "t1", 100_000, 1_000_000)
	enforcer := NewSimpleEnforcer(store)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = enforcer.Check(context.Background(), "t1", Cost{Amount: 1, Currency: "USD", Reason: "test"})
		}()
	}
	wg.Wait()
}

func TestStress_ConcurrentBudgetCheckDailyExhaustion(t *testing.T) {
	store := NewMemoryStorage()
	_ = store.SetLimits(context.Background(), "t1", 100, 10_000)
	enforcer := NewSimpleEnforcer(store)
	denied := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, _ := enforcer.Check(context.Background(), "t1", Cost{Amount: 1, Currency: "USD"})
			if d != nil && !d.Allowed {
				mu.Lock()
				denied++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if denied == 0 {
		t.Fatal("expected at least some denials after exhausting daily limit")
	}
}

func TestStress_ConcurrentMultiTenantChecks(t *testing.T) {
	store := NewMemoryStorage()
	enforcer := NewSimpleEnforcer(store)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tenant := fmt.Sprintf("tenant-%d", n%10)
			_, _ = enforcer.Check(context.Background(), tenant, Cost{Amount: 10, Currency: "USD"})
		}(i)
	}
	wg.Wait()
}

// ────────────────────────────────────────────────────────────────────────
// Risk enforcer with all 4 levels x 10 checks each
// ────────────────────────────────────────────────────────────────────────

func TestStress_RiskEnforcerLowLevel10Checks(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 1000, BlastRadiusCap: 100})
	for i := 0; i < 10; i++ {
		d := re.CheckRisk("t1", RiskLow, 1.0, 1)
		if !d.Allowed {
			t.Fatalf("LOW check %d denied: %s", i, d.Reason)
		}
	}
}

func TestStress_RiskEnforcerMediumLevel10Checks(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 1000, BlastRadiusCap: 100})
	for i := 0; i < 10; i++ {
		d := re.CheckRisk("t1", RiskMedium, 1.0, 1)
		if !d.Allowed {
			t.Fatalf("MEDIUM check %d denied: %s", i, d.Reason)
		}
	}
}

func TestStress_RiskEnforcerHighLevel10Checks(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 1000, BlastRadiusCap: 100})
	for i := 0; i < 10; i++ {
		d := re.CheckRisk("t1", RiskHigh, 1.0, 1)
		if !d.Allowed {
			t.Fatalf("HIGH check %d denied: %s", i, d.Reason)
		}
	}
}

func TestStress_RiskEnforcerCriticalLevel10Checks(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 1000, BlastRadiusCap: 100})
	for i := 0; i < 10; i++ {
		d := re.CheckRisk("t1", RiskCritical, 1.0, 1)
		if !d.Allowed {
			t.Fatalf("CRITICAL check %d denied: %s", i, d.Reason)
		}
	}
}

func TestStress_RiskEnforcerNoTenantDenied(t *testing.T) {
	re := NewRiskEnforcer()
	d := re.CheckRisk("missing", RiskLow, 1.0, 1)
	if d.Allowed {
		t.Fatal("expected fail-closed for missing tenant")
	}
}

func TestStress_RiskEnforcerBlastRadiusExceeded(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 10000, BlastRadiusCap: 5})
	d := re.CheckRisk("t1", RiskLow, 1.0, 10)
	if d.Allowed {
		t.Fatal("expected blast radius exceeded")
	}
}

func TestStress_RiskEnforcerRiskScoreExceeded(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 5, BlastRadiusCap: 1000})
	d := re.CheckRisk("t1", RiskCritical, 1.0, 0)
	if d.Allowed {
		t.Fatal("expected risk score exceeded")
	}
}

func TestStress_RiskEnforcerComputeBudget(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", ComputeCapMillis: 1000})
	d := re.CheckCompute("t1", 500)
	if !d.Allowed {
		t.Fatal("expected compute allowed")
	}
}

func TestStress_RiskEnforcerComputeExceeded(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", ComputeCapMillis: 100})
	d := re.CheckCompute("t1", 200)
	if d.Allowed {
		t.Fatal("expected compute exceeded")
	}
}

func TestStress_RiskEnforcerComputeNoTenant(t *testing.T) {
	re := NewRiskEnforcer()
	d := re.CheckCompute("missing", 100)
	if d.Allowed {
		t.Fatal("expected fail-closed for compute with no tenant")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Autonomy shrink from 100 to 0 in steps
// ────────────────────────────────────────────────────────────────────────

func TestStress_AutonomyShrink100To0(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 100, UncertaintyScore: 0.0})
	for i := 0; i < 10; i++ {
		re.ShrinkAutonomy("t1", 0.1)
	}
	b, _ := re.GetBudget("t1")
	if b.AutonomyLevel != 0 {
		t.Fatalf("expected autonomy 0, got %d", b.AutonomyLevel)
	}
}

func TestStress_AutonomyShrinkSingleStep(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 100, UncertaintyScore: 0.0})
	d := re.ShrinkAutonomy("t1", 0.5)
	if !d.AutonomyShrunk || d.NewAutonomyLevel != 50 {
		t.Fatalf("expected shrink to 50, got %d", d.NewAutonomyLevel)
	}
}

func TestStress_AutonomyShrinkNoTenant(t *testing.T) {
	re := NewRiskEnforcer()
	d := re.ShrinkAutonomy("missing", 0.5)
	if d.Allowed {
		t.Fatal("expected fail-closed for missing tenant")
	}
}

func TestStress_AutonomyShrinkNegativeDelta(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 50, UncertaintyScore: 0.5})
	d := re.ShrinkAutonomy("t1", -0.3)
	if d.NewAutonomyLevel != 80 {
		t.Fatalf("expected autonomy 80, got %d", d.NewAutonomyLevel)
	}
}

func TestStress_AutonomyShrinkClampAbove1(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 100, UncertaintyScore: 0.9})
	re.ShrinkAutonomy("t1", 0.5)
	b, _ := re.GetBudget("t1")
	if b.UncertaintyScore > 1.0 {
		t.Fatalf("uncertainty clamped above 1.0: %f", b.UncertaintyScore)
	}
}

func TestStress_IsAutonomousAllowedLow(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 50})
	if !re.IsAutonomousAllowed("t1", RiskLow) {
		t.Fatal("expected low risk autonomous allowed at autonomy 50")
	}
}

func TestStress_IsAutonomousAllowedCriticalDenied(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 99})
	if re.IsAutonomousAllowed("t1", RiskCritical) {
		t.Fatal("critical should never be autonomous")
	}
}

func TestStress_IsAutonomousAllowedNoTenant(t *testing.T) {
	re := NewRiskEnforcer()
	if re.IsAutonomousAllowed("missing", RiskLow) {
		t.Fatal("expected fail-closed for missing tenant")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Budget reset 24 cycles
// ────────────────────────────────────────────────────────────────────────

func TestStress_BudgetResetDailyOver24Cycles(t *testing.T) {
	store := NewMemoryStorage()
	_ = store.SetLimits(context.Background(), "t1", 10000, 1_000_000)
	enforcer := NewSimpleEnforcer(store)
	for cycle := 0; cycle < 24; cycle++ {
		d, _ := enforcer.Check(context.Background(), "t1", Cost{Amount: 50})
		if d == nil || !d.Allowed {
			t.Fatalf("cycle %d: expected allowed (daily limit 10000, used %d)", cycle, int64(cycle+1)*50)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────
// Enforcement receipt for every decision
// ────────────────────────────────────────────────────────────────────────

func TestStress_EnforcementReceiptOnAllow(t *testing.T) {
	store := NewMemoryStorage()
	_ = store.SetLimits(context.Background(), "t1", 10000, 100000)
	enforcer := NewSimpleEnforcer(store)
	d, _ := enforcer.Check(context.Background(), "t1", Cost{Amount: 10})
	if d.Receipt == nil || d.Receipt.Action != "allowed" {
		t.Fatal("expected allowed receipt")
	}
}

func TestStress_EnforcementReceiptOnDailyDeny(t *testing.T) {
	store := NewMemoryStorage()
	_ = store.SetLimits(context.Background(), "t1", 5, 100000)
	enforcer := NewSimpleEnforcer(store)
	d, _ := enforcer.Check(context.Background(), "t1", Cost{Amount: 10})
	if d.Receipt == nil || d.Receipt.Action != "denied" {
		t.Fatal("expected denied receipt")
	}
}

func TestStress_EnforcementReceiptOnMonthlyDeny(t *testing.T) {
	store := NewMemoryStorage()
	_ = store.SetLimits(context.Background(), "t1", 100000, 5)
	enforcer := NewSimpleEnforcer(store)
	d, _ := enforcer.Check(context.Background(), "t1", Cost{Amount: 10})
	if d.Receipt == nil || d.Receipt.Action != "denied" {
		t.Fatal("expected denied receipt for monthly")
	}
}

func TestStress_EnforcementReceiptHasTimestamp(t *testing.T) {
	store := NewMemoryStorage()
	_ = store.SetLimits(context.Background(), "t1", 10000, 100000)
	enforcer := NewSimpleEnforcer(store)
	d, _ := enforcer.Check(context.Background(), "t1", Cost{Amount: 1})
	if d.Receipt == nil || d.Receipt.Timestamp.IsZero() {
		t.Fatal("receipt missing timestamp")
	}
}

func TestStress_EnforcementReceiptHasID(t *testing.T) {
	store := NewMemoryStorage()
	_ = store.SetLimits(context.Background(), "t1", 10000, 100000)
	enforcer := NewSimpleEnforcer(store)
	d, _ := enforcer.Check(context.Background(), "t1", Cost{Amount: 1})
	if d.Receipt == nil || d.Receipt.ID == "" {
		t.Fatal("receipt missing ID")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Memory store with 100 tenants
// ────────────────────────────────────────────────────────────────────────

func TestStress_MemoryStore100Tenants(t *testing.T) {
	store := NewMemoryStorage()
	for i := 0; i < 100; i++ {
		tid := fmt.Sprintf("tenant-%d", i)
		_ = store.SetLimits(context.Background(), tid, int64(i*100), int64(i*1000))
		_ = store.Set(context.Background(), &Budget{TenantID: tid, DailyLimit: int64(i * 100), MonthlyLimit: int64(i * 1000), LastUpdated: time.Now()})
	}
	for i := 0; i < 100; i++ {
		b, _ := store.Get(context.Background(), fmt.Sprintf("tenant-%d", i))
		if b == nil {
			t.Fatalf("tenant-%d not found", i)
		}
	}
}

func TestStress_MemoryStoreGetNonexistent(t *testing.T) {
	store := NewMemoryStorage()
	b, err := store.Get(context.Background(), "nonexistent")
	if err != nil || b != nil {
		t.Fatal("expected nil for nonexistent tenant")
	}
}

func TestStress_MemoryStoreDefaultLimits(t *testing.T) {
	store := NewMemoryStorage()
	d, m, err := store.Limits(context.Background(), "unknown")
	if err != nil || d != 1000 || m != 50000 {
		t.Fatalf("expected defaults, got d=%d m=%d err=%v", d, m, err)
	}
}

func TestStress_BudgetDailyRemaining(t *testing.T) {
	b := &Budget{DailyLimit: 100, DailyUsed: 60}
	if b.DailyRemaining() != 40 {
		t.Fatalf("expected 40 remaining, got %d", b.DailyRemaining())
	}
}

func TestStress_BudgetMonthlyRemaining(t *testing.T) {
	b := &Budget{MonthlyLimit: 1000, MonthlyUsed: 1200}
	if b.MonthlyRemaining() != 0 {
		t.Fatalf("expected 0 remaining, got %d", b.MonthlyRemaining())
	}
}

func TestStress_GetBudgetViaSelf(t *testing.T) {
	store := NewMemoryStorage()
	enforcer := NewSimpleEnforcer(store)
	_ = store.Set(context.Background(), &Budget{TenantID: "t1", DailyLimit: 100, MonthlyLimit: 1000, LastUpdated: time.Now()})
	b, err := enforcer.GetBudget(context.Background(), "t1")
	if err != nil || b == nil {
		t.Fatal("expected budget via enforcer.GetBudget")
	}
}

func TestStress_SetLimitsViaEnforcer(t *testing.T) {
	store := NewMemoryStorage()
	enforcer := NewSimpleEnforcer(store)
	_ = enforcer.SetLimits(context.Background(), "t1", 999, 9999)
	d, m, _ := store.Limits(context.Background(), "t1")
	if d != 999 || m != 9999 {
		t.Fatalf("expected 999/9999, got %d/%d", d, m)
	}
}

func TestStress_RecordSpendNoOp(t *testing.T) {
	store := NewMemoryStorage()
	enforcer := NewSimpleEnforcer(store)
	err := enforcer.RecordSpend(context.Background(), "t1", Cost{Amount: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStress_RiskWeightsAllDefined(t *testing.T) {
	levels := []RiskLevel{RiskLow, RiskMedium, RiskHigh, RiskCritical}
	for _, l := range levels {
		if _, ok := RiskWeights[l]; !ok {
			t.Fatalf("missing weight for %s", l)
		}
	}
}

func TestStress_RiskWeightValues(t *testing.T) {
	if RiskWeights[RiskLow] != 1.0 || RiskWeights[RiskMedium] != 2.0 || RiskWeights[RiskHigh] != 5.0 || RiskWeights[RiskCritical] != 10.0 {
		t.Fatal("risk weight values mismatch")
	}
}

func TestStress_RiskEnforcerGetBudgetNotFound(t *testing.T) {
	re := NewRiskEnforcer()
	_, err := re.GetBudget("missing")
	if err == nil {
		t.Fatal("expected error for missing tenant")
	}
}

func TestStress_RiskEnforcerGetBudgetFound(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", ComputeCapMillis: 500})
	b, err := re.GetBudget("t1")
	if err != nil || b.ComputeCapMillis != 500 {
		t.Fatal("expected budget to be retrievable")
	}
}

func TestStress_BudgetDailyRemainingNegative(t *testing.T) {
	b := &Budget{DailyLimit: 10, DailyUsed: 50}
	if b.DailyRemaining() != 0 {
		t.Fatalf("expected 0, got %d", b.DailyRemaining())
	}
}
