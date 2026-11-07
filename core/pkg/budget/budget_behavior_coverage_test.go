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

// --- SetBudget / GetBudget ---

// --- CheckRisk per level ---

// --- ShrinkAutonomy ---

// --- IsAutonomousAllowed per threshold ---

// --- ComputeCapMillis ---

// --- BlastRadiusCap ---

// --- RiskScoreCap ---

// --- MemoryStorage ---

// --- NewSimpleEnforcer ---

// --- Check: within / exceeded / boundary ---

// --- Fail-closed on error ---

type failingStorage struct{ MemoryStorage }

func (f *failingStorage) Get(_ context.Context, _ string) (*Budget, error) {
	return nil, errors.New("storage down")
}

type failingSetStorage struct{ MemoryStorage }

func (f *failingSetStorage) Get(_ context.Context, _ string) (*Budget, error) {
	return &Budget{TenantID: "t1", DailyLimit: 9999, MonthlyLimit: 9999, LastUpdated: time.Now()}, nil
}
func (f *failingSetStorage) Set(_ context.Context, _ *Budget) error {
	return errors.New("write failed")
}

// --- Enforcement receipts ---

// --- Budget type fields ---

func TestCost_FieldsAccessible(t *testing.T) {
	c := Cost{Amount: 150, Currency: "USD", Reason: "inference"}
	if c.Amount != 150 || c.Currency != "USD" || c.Reason != "inference" {
		t.Error("Cost fields not set correctly")
	}
}

// --- Additional SimpleEnforcer behaviors ---

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
