package budget

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── 1-5: Risk enforcer with all 4 levels ────────────────────────

func TestDeep_RiskLowAllowed(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 100, BlastRadiusCap: 100, AutonomyLevel: 50})
	d := re.CheckRisk("t1", RiskLow, 1.0, 1)
	if !d.Allowed {
		t.Fatalf("LOW risk should be allowed: %s", d.Reason)
	}
	if d.RiskCost != 1.0 {
		t.Fatalf("LOW weight=1.0, cost should be 1.0, got %f", d.RiskCost)
	}
}

func TestDeep_RiskMediumWeight(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 100, BlastRadiusCap: 100})
	d := re.CheckRisk("t1", RiskMedium, 5.0, 1)
	if d.RiskCost != 10.0 {
		t.Fatalf("MEDIUM weight=2.0, cost should be 10.0, got %f", d.RiskCost)
	}
}

func TestDeep_RiskHighWeight(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 100, BlastRadiusCap: 100})
	d := re.CheckRisk("t1", RiskHigh, 2.0, 1)
	if d.RiskCost != 10.0 {
		t.Fatalf("HIGH weight=5.0, cost should be 10.0, got %f", d.RiskCost)
	}
}

func TestDeep_RiskCriticalWeight(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 100, BlastRadiusCap: 100})
	d := re.CheckRisk("t1", RiskCritical, 1.0, 1)
	if d.RiskCost != 10.0 {
		t.Fatalf("CRITICAL weight=10.0, cost should be 10.0, got %f", d.RiskCost)
	}
}

func TestDeep_RiskAllFourInSequence(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 1000, BlastRadiusCap: 100})
	levels := []RiskLevel{RiskLow, RiskMedium, RiskHigh, RiskCritical}
	for _, l := range levels {
		d := re.CheckRisk("t1", l, 1.0, 1)
		if !d.Allowed {
			t.Fatalf("level %s should be allowed with high cap", l)
		}
	}
}

// ── 6-10: Autonomy shrinking to 0 ──────────────────────────────

func TestDeep_AutonomyShrinkToZero(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 100, UncertaintyScore: 0})
	d := re.ShrinkAutonomy("t1", 1.0)
	if d.NewAutonomyLevel != 0 {
		t.Fatalf("full uncertainty should shrink autonomy to 0, got %d", d.NewAutonomyLevel)
	}
}

func TestDeep_AutonomyShrinkGradual(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 100, UncertaintyScore: 0})
	re.ShrinkAutonomy("t1", 0.5)
	b, _ := re.GetBudget("t1")
	if b.AutonomyLevel != 50 {
		t.Fatalf("0.5 uncertainty should give autonomy 50, got %d", b.AutonomyLevel)
	}
}

func TestDeep_AutonomyClampAbove1(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 100, UncertaintyScore: 0.8})
	re.ShrinkAutonomy("t1", 0.5) // 0.8 + 0.5 = clamped to 1.0
	b, _ := re.GetBudget("t1")
	if b.UncertaintyScore != 1.0 {
		t.Fatalf("uncertainty should clamp to 1.0, got %f", b.UncertaintyScore)
	}
	if b.AutonomyLevel != 0 {
		t.Fatalf("autonomy should be 0 at max uncertainty, got %d", b.AutonomyLevel)
	}
}

func TestDeep_AutonomyNegativeDelta(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 50, UncertaintyScore: 0.5})
	d := re.ShrinkAutonomy("t1", -0.3)
	if d.NewAutonomyLevel != 80 { // (1.0 - 0.2) * 100 = 80
		t.Fatalf("negative delta should increase autonomy, got %d", d.NewAutonomyLevel)
	}
}

func TestDeep_AutonomyNoTenant(t *testing.T) {
	re := NewRiskEnforcer()
	d := re.ShrinkAutonomy("unknown", 0.5)
	if d.Allowed {
		t.Error("no budget = fail-closed")
	}
}

// ── 11-15: Blast radius at exact cap ────────────────────────────

func TestDeep_BlastRadiusExactCap(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 1000, BlastRadiusCap: 10})
	d := re.CheckRisk("t1", RiskLow, 0.1, 10)
	if !d.Allowed {
		t.Error("blast radius at exact cap should be allowed")
	}
}

func TestDeep_BlastRadiusOverCap(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 1000, BlastRadiusCap: 10})
	d := re.CheckRisk("t1", RiskLow, 0.1, 11)
	if d.Allowed {
		t.Error("blast radius over cap should be denied")
	}
}

func TestDeep_BlastRadiusCumulative(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 1000, BlastRadiusCap: 5})
	re.CheckRisk("t1", RiskLow, 0.1, 3)
	d := re.CheckRisk("t1", RiskLow, 0.1, 3) // 3+3=6 > 5
	if d.Allowed {
		t.Error("cumulative blast radius over cap should deny")
	}
}

func TestDeep_RiskScoreExactCap(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 10, BlastRadiusCap: 100})
	d := re.CheckRisk("t1", RiskLow, 10.0, 1)
	if !d.Allowed {
		t.Error("risk score at exact cap should be allowed")
	}
}

func TestDeep_RiskScoreOverCap(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 10, BlastRadiusCap: 100})
	d := re.CheckRisk("t1", RiskLow, 10.1, 1) // 10.1 > 10
	if d.Allowed {
		t.Error("risk score over cap should be denied")
	}
}

// ── 16-20: Concurrent budget checks (100 goroutines) ────────────

func TestDeep_ConcurrentBudgetChecks(t *testing.T) {
	store := NewMemoryStorage()
	store.SetLimits(context.Background(), "t1", 10000, 100000)
	enforcer := NewSimpleEnforcer(store)
	var wg sync.WaitGroup
	allowed := int32(0)
	var mu sync.Mutex
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, _ := enforcer.Check(context.Background(), "t1", Cost{Amount: 10, Currency: "USD"})
			if d != nil && d.Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	// 100 * 10 = 1000 < 10000 daily limit, all should be allowed
	if allowed != 100 {
		t.Fatalf("all 100 checks should be allowed, got %d", allowed)
	}
}

func TestDeep_ConcurrentRiskChecks(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 10000, BlastRadiusCap: 10000})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			re.CheckRisk("t1", RiskLow, 1.0, 1)
		}()
	}
	wg.Wait()
	b, _ := re.GetBudget("t1")
	if b.RiskScoreUsed != 100.0 {
		t.Fatalf("want 100.0 risk used got %f", b.RiskScoreUsed)
	}
}

func TestDeep_ConcurrentComputeChecks(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", ComputeCapMillis: 100000})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			re.CheckCompute("t1", 10)
		}()
	}
	wg.Wait()
	b, _ := re.GetBudget("t1")
	if b.ComputeUsedMillis != 1000 {
		t.Fatalf("want 1000ms used got %d", b.ComputeUsedMillis)
	}
}

func TestDeep_ConcurrentAutonomyShrink(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 100, UncertaintyScore: 0})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			re.ShrinkAutonomy("t1", 0.01)
		}()
	}
	wg.Wait()
	b, _ := re.GetBudget("t1")
	if b.UncertaintyScore > 1.0 {
		t.Error("uncertainty should not exceed 1.0")
	}
}

func TestDeep_ConcurrentIsAutonomous(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 50})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			re.IsAutonomousAllowed("t1", RiskLow)
			re.IsAutonomousAllowed("t1", RiskHigh)
		}()
	}
	wg.Wait()
}

// ── 21-25: Budget reset at day/month boundaries ─────────────────

func TestDeep_DailyReset(t *testing.T) {
	store := NewMemoryStorage()
	enforcer := NewSimpleEnforcer(store)
	yesterday := time.Now().UTC().Add(-25 * time.Hour)
	store.Set(context.Background(), &Budget{
		TenantID: "t1", DailyLimit: 1000, MonthlyLimit: 10000,
		DailyUsed: 999, MonthlyUsed: 500, LastUpdated: yesterday,
	})
	d, _ := enforcer.Check(context.Background(), "t1", Cost{Amount: 100})
	if !d.Allowed {
		t.Fatalf("daily reset should allow: %s", d.Reason)
	}
}

func TestDeep_MonthlyReset(t *testing.T) {
	store := NewMemoryStorage()
	enforcer := NewSimpleEnforcer(store)
	lastMonth := time.Now().UTC().AddDate(0, -1, 0)
	store.Set(context.Background(), &Budget{
		TenantID: "t1", DailyLimit: 1000, MonthlyLimit: 1000,
		DailyUsed: 0, MonthlyUsed: 999, LastUpdated: lastMonth,
	})
	d, _ := enforcer.Check(context.Background(), "t1", Cost{Amount: 100})
	if !d.Allowed {
		t.Fatalf("monthly reset should allow: %s", d.Reason)
	}
}

func TestDeep_DailyLimitExact(t *testing.T) {
	store := NewMemoryStorage()
	enforcer := NewSimpleEnforcer(store)
	store.Set(context.Background(), &Budget{
		TenantID: "t1", DailyLimit: 100, MonthlyLimit: 10000,
		LastUpdated: time.Now().UTC(),
	})
	d, _ := enforcer.Check(context.Background(), "t1", Cost{Amount: 100})
	if !d.Allowed {
		t.Fatal("at exact daily limit should be allowed")
	}
	d, _ = enforcer.Check(context.Background(), "t1", Cost{Amount: 1})
	if d.Allowed {
		t.Fatal("over daily limit should be denied")
	}
}

func TestDeep_BudgetRemainingHelpers(t *testing.T) {
	b := &Budget{DailyLimit: 100, DailyUsed: 120, MonthlyLimit: 500, MonthlyUsed: 600}
	if b.DailyRemaining() != 0 {
		t.Fatalf("over-budget daily remaining should be 0, got %d", b.DailyRemaining())
	}
	if b.MonthlyRemaining() != 0 {
		t.Fatalf("over-budget monthly remaining should be 0, got %d", b.MonthlyRemaining())
	}
}

func TestDeep_AutonomyThresholds(t *testing.T) {
	re := NewRiskEnforcer()
	re.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 50})
	if !re.IsAutonomousAllowed("t1", RiskLow) {
		t.Error("autonomy 50 >= threshold 10 for LOW")
	}
	if !re.IsAutonomousAllowed("t1", RiskMedium) {
		t.Error("autonomy 50 >= threshold 40 for MEDIUM")
	}
	if re.IsAutonomousAllowed("t1", RiskHigh) {
		t.Error("autonomy 50 < threshold 70 for HIGH")
	}
	if re.IsAutonomousAllowed("t1", RiskCritical) {
		t.Error(fmt.Sprintf("CRITICAL should never be autonomous"))
	}
}
