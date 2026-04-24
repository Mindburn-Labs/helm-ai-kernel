package budget

import (
	"context"
	"errors"
	"testing"
	"time"
)

// --- RiskWeights (4 levels) ---

func TestRiskWeights_LowIsOne(t *testing.T) {
	if RiskWeights[RiskLow] != 1.0 {
		t.Errorf("LOW weight should be 1.0, got %f", RiskWeights[RiskLow])
	}
}

func TestRiskWeights_MediumIsTwo(t *testing.T) {
	if RiskWeights[RiskMedium] != 2.0 {
		t.Errorf("MEDIUM weight should be 2.0, got %f", RiskWeights[RiskMedium])
	}
}

func TestRiskWeights_HighIsFive(t *testing.T) {
	if RiskWeights[RiskHigh] != 5.0 {
		t.Errorf("HIGH weight should be 5.0, got %f", RiskWeights[RiskHigh])
	}
}

func TestRiskWeights_CriticalIsTen(t *testing.T) {
	if RiskWeights[RiskCritical] != 10.0 {
		t.Errorf("CRITICAL weight should be 10.0, got %f", RiskWeights[RiskCritical])
	}
}

// --- NewRiskEnforcer ---

func TestNewRiskEnforcer_NotNil(t *testing.T) {
	e := NewRiskEnforcer()
	if e == nil {
		t.Fatal("NewRiskEnforcer returned nil")
	}
}

func TestNewRiskEnforcer_EmptyBudgets(t *testing.T) {
	e := NewRiskEnforcer()
	_, err := e.GetBudget("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

// --- SetBudget / GetBudget ---

func TestSetBudget_StoresAndRetrieves(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", ComputeCapMillis: 5000})
	b, err := e.GetBudget("t1")
	if err != nil || b.ComputeCapMillis != 5000 {
		t.Fatalf("expected ComputeCapMillis=5000, got %d (err=%v)", b.ComputeCapMillis, err)
	}
}

func TestSetBudget_OverwritesPrevious(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", BlastRadiusCap: 10})
	e.SetBudget(&RiskBudget{TenantID: "t1", BlastRadiusCap: 99})
	b, _ := e.GetBudget("t1")
	if b.BlastRadiusCap != 99 {
		t.Fatalf("expected overwritten BlastRadiusCap=99, got %d", b.BlastRadiusCap)
	}
}

func TestGetBudget_ErrorForMissingTenant(t *testing.T) {
	e := NewRiskEnforcer()
	_, err := e.GetBudget("missing")
	if err == nil {
		t.Fatal("expected error for missing tenant")
	}
}

// --- CheckRisk per level ---

func TestCheckRisk_LowAllowed(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 100, BlastRadiusCap: 50})
	d := e.CheckRisk("t1", RiskLow, 10.0, 1)
	if !d.Allowed || d.RiskCost != 10.0 {
		t.Errorf("LOW risk: allowed=%v cost=%f", d.Allowed, d.RiskCost)
	}
}

func TestCheckRisk_MediumDoublesCost(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 100, BlastRadiusCap: 50})
	d := e.CheckRisk("t1", RiskMedium, 10.0, 1)
	if d.RiskCost != 20.0 {
		t.Errorf("MEDIUM risk cost should be 20.0, got %f", d.RiskCost)
	}
}

func TestCheckRisk_HighMultipliesByFive(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 500, BlastRadiusCap: 50})
	d := e.CheckRisk("t1", RiskHigh, 10.0, 1)
	if d.RiskCost != 50.0 {
		t.Errorf("HIGH risk cost should be 50.0, got %f", d.RiskCost)
	}
}

func TestCheckRisk_CriticalMultipliesByTen(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 500, BlastRadiusCap: 50})
	d := e.CheckRisk("t1", RiskCritical, 10.0, 1)
	if d.RiskCost != 100.0 {
		t.Errorf("CRITICAL risk cost should be 100.0, got %f", d.RiskCost)
	}
}

// --- ShrinkAutonomy ---

func TestShrinkAutonomy_IncreasesUncertainty(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 100, UncertaintyScore: 0.0})
	d := e.ShrinkAutonomy("t1", 0.3)
	if d.NewAutonomyLevel != 70 {
		t.Errorf("expected autonomy 70, got %d", d.NewAutonomyLevel)
	}
}

func TestShrinkAutonomy_ClampsUncertaintyAtOne(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 50, UncertaintyScore: 0.8})
	e.ShrinkAutonomy("t1", 0.5) // 0.8+0.5=1.3, clamped to 1.0
	b, _ := e.GetBudget("t1")
	if b.UncertaintyScore != 1.0 {
		t.Errorf("expected uncertainty clamped to 1.0, got %f", b.UncertaintyScore)
	}
}

func TestShrinkAutonomy_ClampsUncertaintyAtZero(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 50, UncertaintyScore: 0.2})
	e.ShrinkAutonomy("t1", -0.5) // 0.2-0.5=-0.3, clamped to 0.0
	b, _ := e.GetBudget("t1")
	if b.UncertaintyScore != 0.0 {
		t.Errorf("expected uncertainty clamped to 0.0, got %f", b.UncertaintyScore)
	}
}

func TestShrinkAutonomy_ReportsShrunk(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 80, UncertaintyScore: 0.2})
	d := e.ShrinkAutonomy("t1", 0.3) // uncertainty 0.5 → autonomy 50
	if !d.AutonomyShrunk {
		t.Error("expected AutonomyShrunk=true")
	}
}

func TestShrinkAutonomy_NotShrunkWhenDecreased(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 50, UncertaintyScore: 0.5})
	d := e.ShrinkAutonomy("t1", -0.2) // uncertainty 0.3 → autonomy 70 (increased)
	if d.AutonomyShrunk {
		t.Error("expected AutonomyShrunk=false when autonomy increased")
	}
}

// --- IsAutonomousAllowed per threshold ---

func TestIsAutonomousAllowed_LowAt10(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 10})
	if !e.IsAutonomousAllowed("t1", RiskLow) {
		t.Error("LOW risk should be allowed at autonomy=10")
	}
}

func TestIsAutonomousAllowed_LowDeniedBelow10(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 9})
	if e.IsAutonomousAllowed("t1", RiskLow) {
		t.Error("LOW risk should be denied at autonomy=9")
	}
}

func TestIsAutonomousAllowed_MediumAt40(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 40})
	if !e.IsAutonomousAllowed("t1", RiskMedium) {
		t.Error("MEDIUM risk should be allowed at autonomy=40")
	}
}

func TestIsAutonomousAllowed_MediumDeniedBelow40(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 39})
	if e.IsAutonomousAllowed("t1", RiskMedium) {
		t.Error("MEDIUM risk should be denied at autonomy=39")
	}
}

func TestIsAutonomousAllowed_HighAt70(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 70})
	if !e.IsAutonomousAllowed("t1", RiskHigh) {
		t.Error("HIGH risk should be allowed at autonomy=70")
	}
}

func TestIsAutonomousAllowed_HighDeniedBelow70(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 69})
	if e.IsAutonomousAllowed("t1", RiskHigh) {
		t.Error("HIGH risk should be denied at autonomy=69")
	}
}

func TestIsAutonomousAllowed_CriticalDeniedBelow100(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", AutonomyLevel: 99})
	if e.IsAutonomousAllowed("t1", RiskCritical) {
		t.Error("CRITICAL risk should be denied at autonomy=99")
	}
}

// --- ComputeCapMillis ---

func TestCheckCompute_WithinBudget(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", ComputeCapMillis: 10000})
	d := e.CheckCompute("t1", 5000)
	if !d.Allowed {
		t.Errorf("expected allowed, got: %s", d.Reason)
	}
}

func TestCheckCompute_ExactlyAtCap(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", ComputeCapMillis: 10000})
	d := e.CheckCompute("t1", 10000)
	if !d.Allowed {
		t.Error("expected allowed when exactly at cap")
	}
}

func TestCheckCompute_ExceedsCap(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", ComputeCapMillis: 10000})
	d := e.CheckCompute("t1", 10001)
	if d.Allowed {
		t.Error("expected denied when exceeding cap")
	}
}

func TestCheckCompute_AccumulatesUsage(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", ComputeCapMillis: 100})
	e.CheckCompute("t1", 60)
	d := e.CheckCompute("t1", 50) // 60+50=110 > 100
	if d.Allowed {
		t.Error("expected denied after accumulated usage exceeds cap")
	}
}

// --- BlastRadiusCap ---

func TestBlastRadius_WithinCap(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 1000, BlastRadiusCap: 10})
	d := e.CheckRisk("t1", RiskLow, 1.0, 10)
	if !d.Allowed {
		t.Errorf("expected allowed at blast radius cap, got: %s", d.Reason)
	}
}

func TestBlastRadius_ExceedsCap(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 1000, BlastRadiusCap: 10})
	d := e.CheckRisk("t1", RiskLow, 1.0, 11)
	if d.Allowed {
		t.Error("expected denied when blast radius exceeds cap")
	}
}

// --- RiskScoreCap ---

func TestRiskScore_ExactlyAtCap(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 10.0, BlastRadiusCap: 100})
	d := e.CheckRisk("t1", RiskLow, 10.0, 1) // cost=10, cap=10
	if !d.Allowed {
		t.Error("expected allowed when risk score exactly equals cap")
	}
}

func TestRiskScore_JustOverCap(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(&RiskBudget{TenantID: "t1", RiskScoreCap: 9.9, BlastRadiusCap: 100})
	d := e.CheckRisk("t1", RiskLow, 10.0, 1) // cost=10 > 9.9
	if d.Allowed {
		t.Error("expected denied when risk score exceeds cap")
	}
}

// --- MemoryStorage ---

func TestMemoryStorage_GetReturnsNilForMissing(t *testing.T) {
	s := NewMemoryStorage()
	b, err := s.Get(context.Background(), "missing")
	if err != nil || b != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", b, err)
	}
}

func TestMemoryStorage_SetAndGet(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()
	budget := &Budget{TenantID: "t1", DailyLimit: 500, MonthlyLimit: 5000}
	_ = s.Set(ctx, budget)
	b, err := s.Get(ctx, "t1")
	if err != nil || b.DailyLimit != 500 {
		t.Errorf("expected DailyLimit=500, got %d (err=%v)", b.DailyLimit, err)
	}
}

func TestMemoryStorage_SetReturnsCopy(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()
	budget := &Budget{TenantID: "t1", DailyUsed: 100}
	_ = s.Set(ctx, budget)
	budget.DailyUsed = 999 // mutate original
	b, _ := s.Get(ctx, "t1")
	if b.DailyUsed != 100 {
		t.Error("Set should store a copy, not a reference")
	}
}

func TestMemoryStorage_GetReturnsCopy(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()
	_ = s.Set(ctx, &Budget{TenantID: "t1", DailyUsed: 100})
	b1, _ := s.Get(ctx, "t1")
	b1.DailyUsed = 999 // mutate returned value
	b2, _ := s.Get(ctx, "t1")
	if b2.DailyUsed != 100 {
		t.Error("Get should return a copy, not a reference to stored data")
	}
}

func TestMemoryStorage_LimitsDefault(t *testing.T) {
	s := NewMemoryStorage()
	d, m, err := s.Limits(context.Background(), "new-tenant")
	if err != nil || d != 1000 || m != 50000 {
		t.Errorf("expected defaults (1000, 50000), got (%d, %d, %v)", d, m, err)
	}
}

func TestMemoryStorage_SetLimitsAndGet(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()
	_ = s.SetLimits(ctx, "t1", 2000, 80000)
	d, m, err := s.Limits(ctx, "t1")
	if err != nil || d != 2000 || m != 80000 {
		t.Errorf("expected (2000, 80000), got (%d, %d, %v)", d, m, err)
	}
}

// --- NewSimpleEnforcer ---

func TestNewSimpleEnforcer_NotNil(t *testing.T) {
	e := NewSimpleEnforcer(NewMemoryStorage())
	if e == nil {
		t.Fatal("NewSimpleEnforcer returned nil")
	}
}

// --- Check: within / exceeded / boundary ---

func TestSimpleEnforcer_CheckWithinLimits(t *testing.T) {
	s := NewMemoryStorage()
	e := NewSimpleEnforcer(s)
	ctx := context.Background()
	d, err := e.Check(ctx, "t1", Cost{Amount: 100, Currency: "USD", Reason: "test"})
	if err != nil || !d.Allowed {
		t.Errorf("expected allowed within default limits, got allowed=%v err=%v", d.Allowed, err)
	}
}

func TestSimpleEnforcer_CheckDailyLimitExceeded(t *testing.T) {
	s := NewMemoryStorage()
	_ = s.SetLimits(context.Background(), "t1", 100, 50000)
	e := NewSimpleEnforcer(s)
	ctx := context.Background()
	_, _ = e.Check(ctx, "t1", Cost{Amount: 80})
	d, _ := e.Check(ctx, "t1", Cost{Amount: 30}) // 80+30=110 > 100
	if d.Allowed {
		t.Error("expected denied when daily limit exceeded")
	}
}

func TestSimpleEnforcer_CheckMonthlyLimitExceeded(t *testing.T) {
	s := NewMemoryStorage()
	_ = s.SetLimits(context.Background(), "t1", 50000, 100)
	e := NewSimpleEnforcer(s)
	ctx := context.Background()
	_, _ = e.Check(ctx, "t1", Cost{Amount: 80})
	d, _ := e.Check(ctx, "t1", Cost{Amount: 30}) // 80+30=110 > 100
	if d.Allowed {
		t.Error("expected denied when monthly limit exceeded")
	}
}

func TestSimpleEnforcer_CheckExactlyAtDailyLimit(t *testing.T) {
	s := NewMemoryStorage()
	_ = s.SetLimits(context.Background(), "t1", 100, 50000)
	e := NewSimpleEnforcer(s)
	d, _ := e.Check(context.Background(), "t1", Cost{Amount: 100})
	if !d.Allowed {
		t.Error("expected allowed when exactly at daily limit")
	}
}

// --- Fail-closed on error ---

type failingStorage struct{ MemoryStorage }

func (f *failingStorage) Get(_ context.Context, _ string) (*Budget, error) {
	return nil, errors.New("storage down")
}

func TestSimpleEnforcer_FailClosedOnGetError(t *testing.T) {
	e := NewSimpleEnforcer(&failingStorage{})
	d, err := e.Check(context.Background(), "t1", Cost{Amount: 1})
	if err == nil {
		t.Fatal("expected error propagation")
	}
	if d.Allowed {
		t.Error("expected fail-closed on storage error")
	}
}

type failingSetStorage struct{ MemoryStorage }

func (f *failingSetStorage) Get(_ context.Context, _ string) (*Budget, error) {
	return &Budget{TenantID: "t1", DailyLimit: 9999, MonthlyLimit: 9999, LastUpdated: time.Now()}, nil
}
func (f *failingSetStorage) Set(_ context.Context, _ *Budget) error {
	return errors.New("write failed")
}

func TestSimpleEnforcer_FailClosedOnSetError(t *testing.T) {
	e := NewSimpleEnforcer(&failingSetStorage{})
	d, err := e.Check(context.Background(), "t1", Cost{Amount: 1})
	if err == nil {
		t.Fatal("expected error from Set failure")
	}
	if d.Allowed {
		t.Error("expected fail-closed on write error")
	}
}

// --- Enforcement receipts ---

func TestReceipt_AllowedAction(t *testing.T) {
	e := NewSimpleEnforcer(NewMemoryStorage())
	d, _ := e.Check(context.Background(), "t1", Cost{Amount: 1})
	if d.Receipt == nil || d.Receipt.Action != "allowed" {
		t.Error("expected receipt with action=allowed")
	}
}

func TestReceipt_DeniedAction(t *testing.T) {
	s := NewMemoryStorage()
	_ = s.SetLimits(context.Background(), "t1", 10, 50000)
	e := NewSimpleEnforcer(s)
	ctx := context.Background()
	_, _ = e.Check(ctx, "t1", Cost{Amount: 10})
	d, _ := e.Check(ctx, "t1", Cost{Amount: 5}) // exceeds
	if d.Receipt == nil || d.Receipt.Action != "denied" {
		t.Error("expected receipt with action=denied")
	}
}

func TestReceipt_ContainsTenantID(t *testing.T) {
	e := NewSimpleEnforcer(NewMemoryStorage())
	d, _ := e.Check(context.Background(), "my-tenant", Cost{Amount: 1})
	if d.Receipt.TenantID != "my-tenant" {
		t.Errorf("expected TenantID=my-tenant, got %s", d.Receipt.TenantID)
	}
}

func TestReceipt_ContainsCostCents(t *testing.T) {
	e := NewSimpleEnforcer(NewMemoryStorage())
	d, _ := e.Check(context.Background(), "t1", Cost{Amount: 42})
	if d.Receipt.CostCents != 42 {
		t.Errorf("expected CostCents=42, got %d", d.Receipt.CostCents)
	}
}

func TestReceipt_HasNonEmptyID(t *testing.T) {
	e := NewSimpleEnforcer(NewMemoryStorage())
	d, _ := e.Check(context.Background(), "t1", Cost{Amount: 1})
	if d.Receipt.ID == "" {
		t.Error("expected non-empty receipt ID")
	}
}

// --- Budget type fields ---

func TestBudget_DailyRemainingPositive(t *testing.T) {
	b := &Budget{DailyLimit: 1000, DailyUsed: 300}
	if b.DailyRemaining() != 700 {
		t.Errorf("expected 700, got %d", b.DailyRemaining())
	}
}

func TestBudget_DailyRemainingZeroWhenOverdrawn(t *testing.T) {
	b := &Budget{DailyLimit: 100, DailyUsed: 200}
	if b.DailyRemaining() != 0 {
		t.Errorf("expected 0 when overdrawn, got %d", b.DailyRemaining())
	}
}

func TestBudget_MonthlyRemainingPositive(t *testing.T) {
	b := &Budget{MonthlyLimit: 5000, MonthlyUsed: 1000}
	if b.MonthlyRemaining() != 4000 {
		t.Errorf("expected 4000, got %d", b.MonthlyRemaining())
	}
}

func TestBudget_MonthlyRemainingZeroWhenOverdrawn(t *testing.T) {
	b := &Budget{MonthlyLimit: 100, MonthlyUsed: 200}
	if b.MonthlyRemaining() != 0 {
		t.Errorf("expected 0 when overdrawn, got %d", b.MonthlyRemaining())
	}
}

func TestCost_FieldsAccessible(t *testing.T) {
	c := Cost{Amount: 150, Currency: "USD", Reason: "inference"}
	if c.Amount != 150 || c.Currency != "USD" || c.Reason != "inference" {
		t.Error("Cost fields not set correctly")
	}
}

func TestDecision_RemainingReflectsBudget(t *testing.T) {
	e := NewSimpleEnforcer(NewMemoryStorage())
	d, _ := e.Check(context.Background(), "t1", Cost{Amount: 50})
	if d.Remaining == nil {
		t.Fatal("expected Remaining budget in decision")
	}
	if d.Remaining.DailyUsed != 50 {
		t.Errorf("expected DailyUsed=50, got %d", d.Remaining.DailyUsed)
	}
}

// --- Additional SimpleEnforcer behaviors ---

func TestSimpleEnforcer_GetBudgetDelegates(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()
	_ = s.Set(ctx, &Budget{TenantID: "t1", DailyLimit: 42})
	e := NewSimpleEnforcer(s)
	b, err := e.GetBudget(ctx, "t1")
	if err != nil || b.DailyLimit != 42 {
		t.Errorf("expected DailyLimit=42, got %d (err=%v)", b.DailyLimit, err)
	}
}

func TestSimpleEnforcer_SetLimitsDelegates(t *testing.T) {
	s := NewMemoryStorage()
	e := NewSimpleEnforcer(s)
	ctx := context.Background()
	err := e.SetLimits(ctx, "t1", 200, 3000)
	if err != nil {
		t.Fatal(err)
	}
	d, m, _ := s.Limits(ctx, "t1")
	if d != 200 || m != 3000 {
		t.Errorf("expected (200, 3000), got (%d, %d)", d, m)
	}
}

func TestRiskBudget_FieldsAccessible(t *testing.T) {
	rb := RiskBudget{
		TenantID:         "t1",
		ComputeCapMillis: 1000,
		BlastRadiusCap:   50,
		RiskScoreCap:     100.0,
		AutonomyLevel:    80,
		UncertaintyScore: 0.2,
	}
	if rb.TenantID != "t1" || rb.AutonomyLevel != 80 {
		t.Error("RiskBudget fields not accessible")
	}
}
