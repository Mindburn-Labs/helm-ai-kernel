package budget

import (
	"testing"
	"time"
)

func testBudget() *RiskBudget {
	return &RiskBudget{
		TenantID:         "tenant-1",
		ComputeCapMillis: 60000,
		BlastRadiusCap:   100,
		RiskScoreCap:     500.0,
		AutonomyLevel:    80,
		UncertaintyScore: 0.2,
	}
}

func TestRiskCheckAllowed(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(testBudget())

	d := e.CheckRisk("tenant-1", RiskLow, 10.0, 5)
	if !d.Allowed {
		t.Fatalf("expected allowed, got: %s", d.Reason)
	}
	if d.RiskCost != 10.0 {
		t.Fatalf("expected risk cost 10.0, got %.1f", d.RiskCost)
	}
}

func TestRiskCheckWeighted(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(testBudget())

	d := e.CheckRisk("tenant-1", RiskHigh, 10.0, 5)
	if !d.Allowed {
		t.Fatalf("expected allowed, got: %s", d.Reason)
	}
	if d.RiskCost != 50.0 { // 10 * 5.0 (HIGH weight)
		t.Fatalf("expected risk cost 50.0, got %.1f", d.RiskCost)
	}
}

func TestRiskScoreExceeded(t *testing.T) {
	e := NewRiskEnforcer()
	b := testBudget()
	b.RiskScoreCap = 20.0
	e.SetBudget(b)

	d := e.CheckRisk("tenant-1", RiskHigh, 10.0, 5) // 10 * 5.0 = 50 > 20
	if d.Allowed {
		t.Fatal("expected risk score exceeded denial")
	}
}

func TestBlastRadiusExceeded(t *testing.T) {
	e := NewRiskEnforcer()
	b := testBudget()
	b.BlastRadiusCap = 3
	e.SetBudget(b)

	d := e.CheckRisk("tenant-1", RiskLow, 1.0, 5)
	if d.Allowed {
		t.Fatal("expected blast radius exceeded denial")
	}
}

func TestComputeBudgetAllowed(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(testBudget())

	d := e.CheckCompute("tenant-1", 30000)
	if !d.Allowed {
		t.Fatalf("expected allowed, got: %s", d.Reason)
	}
}

func TestComputeBudgetExceeded(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(testBudget()) // 60000ms

	e.CheckCompute("tenant-1", 50000)
	d := e.CheckCompute("tenant-1", 20000) // 50000 + 20000 > 60000
	if d.Allowed {
		t.Fatal("expected compute budget exceeded")
	}
}

func TestAutonomyShrink(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(testBudget()) // AutonomyLevel=80, uncertainty=0.2

	d := e.ShrinkAutonomy("tenant-1", 0.5) // uncertainty → 0.7
	if !d.AutonomyShrunk {
		t.Fatal("expected autonomy to shrink")
	}
	if d.NewAutonomyLevel >= 80 {
		t.Fatalf("expected lower autonomy, got %d", d.NewAutonomyLevel)
	}
}

func TestAutonomyShrinkToZero(t *testing.T) {
	e := NewRiskEnforcer()
	b := testBudget()
	b.UncertaintyScore = 0.0
	b.AutonomyLevel = 100
	e.SetBudget(b)

	d := e.ShrinkAutonomy("tenant-1", 1.0) // uncertainty → 1.0
	if d.NewAutonomyLevel != 0 {
		t.Fatalf("expected autonomy 0 at max uncertainty, got %d", d.NewAutonomyLevel)
	}
}

func TestIsAutonomousAllowed(t *testing.T) {
	e := NewRiskEnforcer()
	e.SetBudget(testBudget()) // AutonomyLevel=80

	if !e.IsAutonomousAllowed("tenant-1", RiskLow) {
		t.Fatal("expected LOW risk allowed at autonomy 80")
	}
	if !e.IsAutonomousAllowed("tenant-1", RiskMedium) {
		t.Fatal("expected MEDIUM risk allowed at autonomy 80")
	}
	if !e.IsAutonomousAllowed("tenant-1", RiskHigh) {
		t.Fatal("expected HIGH risk allowed at autonomy 80")
	}
	if e.IsAutonomousAllowed("tenant-1", RiskCritical) {
		t.Fatal("expected CRITICAL risk denied regardless of autonomy")
	}
}

func TestFailClosedNoBudget(t *testing.T) {
	e := NewRiskEnforcer()

	d := e.CheckRisk("unknown", RiskLow, 1.0, 1)
	if d.Allowed {
		t.Fatal("expected fail-closed without budget")
	}

	d2 := e.CheckCompute("unknown", 1000)
	if d2.Allowed {
		t.Fatal("expected fail-closed without budget")
	}

	if e.IsAutonomousAllowed("unknown", RiskLow) {
		t.Fatal("expected fail-closed without budget")
	}
}

func TestRiskBudgetReservation(t *testing.T) {
	e := NewRiskEnforcer()
	b := testBudget()
	b.RiskScoreCap = 100.0
	e.SetBudget(b)

	// Two LOW risk actions of 40 each = 80 total, should fit
	d1 := e.CheckRisk("tenant-1", RiskLow, 40.0, 1)
	if !d1.Allowed {
		t.Fatal("first action should be allowed")
	}
	d2 := e.CheckRisk("tenant-1", RiskLow, 40.0, 1)
	if !d2.Allowed {
		t.Fatal("second action should be allowed")
	}
	// Third would exceed: 80 + 40 = 120 > 100
	d3 := e.CheckRisk("tenant-1", RiskLow, 40.0, 1)
	if d3.Allowed {
		t.Fatal("third action should be denied (120 > 100)")
	}
}

func TestRiskEnforcer_WithClockAndGetBudget_IsReachable(t *testing.T) {
	e := NewRiskEnforcer().WithClock(func() time.Time { return time.Unix(0, 0).UTC() })
	e.SetBudget(testBudget())

	b, err := e.GetBudget("tenant-1")
	if err != nil {
		t.Fatalf("GetBudget failed: %v", err)
	}
	if b.TenantID != "tenant-1" {
		t.Fatalf("unexpected tenant id %q", b.TenantID)
	}
}
