package observability

import (
	"testing"
	"time"
)

func TestSLOSetTarget(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{
		SLOID:       "slo-1",
		Operation:   "compile",
		LatencyP99:  500 * time.Millisecond,
		SuccessRate: 0.999,
		WindowHours: 24,
	})

	status, err := tracker.Status("compile")
	if err != nil {
		t.Fatal(err)
	}
	if !status.InCompliance {
		t.Fatal("expected compliance with no observations")
	}
}

func TestSLOInCompliance(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{
		SLOID:       "slo-1",
		Operation:   "execute",
		LatencyP99:  1000 * time.Millisecond,
		SuccessRate: 0.99,
		WindowHours: 1,
	})

	// Add 100 successful observations under latency target
	for i := 0; i < 100; i++ {
		tracker.Record(SLOObservation{Operation: "execute", Latency: 100 * time.Millisecond, Success: true})
	}

	status, _ := tracker.Status("execute")
	if !status.InCompliance {
		t.Fatal("expected in compliance")
	}
	if status.CurrentSuccess != 1.0 {
		t.Fatalf("expected 100%% success rate, got %.2f", status.CurrentSuccess)
	}
}

func TestSLOOutOfCompliance(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{
		SLOID:       "slo-1",
		Operation:   "verify",
		LatencyP99:  500 * time.Millisecond,
		SuccessRate: 0.99,
		WindowHours: 1,
	})

	// Add 90 success + 10 failures = 90% (below 99% target)
	for i := 0; i < 90; i++ {
		tracker.Record(SLOObservation{Operation: "verify", Latency: 100 * time.Millisecond, Success: true})
	}
	for i := 0; i < 10; i++ {
		tracker.Record(SLOObservation{Operation: "verify", Latency: 100 * time.Millisecond, Success: false})
	}

	status, _ := tracker.Status("verify")
	if status.InCompliance {
		t.Fatal("expected out of compliance")
	}
}

func TestSLOBurnRate(t *testing.T) {
	tracker := NewSLOTracker()
	tracker.SetTarget(&SLOTarget{
		SLOID:       "slo-1",
		Operation:   "plan",
		LatencyP99:  1000 * time.Millisecond,
		SuccessRate: 0.99, // 1% error budget
		WindowHours: 1,
	})

	// 5% error rate → burn rate = 5x
	for i := 0; i < 95; i++ {
		tracker.Record(SLOObservation{Operation: "plan", Latency: 10 * time.Millisecond, Success: true})
	}
	for i := 0; i < 5; i++ {
		tracker.Record(SLOObservation{Operation: "plan", Latency: 10 * time.Millisecond, Success: false})
	}

	status, _ := tracker.Status("plan")
	if status.BurnRate < 4.0 {
		t.Fatalf("expected high burn rate, got %.2f", status.BurnRate)
	}
}

func TestSLONoTarget(t *testing.T) {
	tracker := NewSLOTracker()
	_, err := tracker.Status("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing target")
	}
}
