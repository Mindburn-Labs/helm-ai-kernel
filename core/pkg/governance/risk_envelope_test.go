package governance

import (
	"testing"
	"time"
)

func TestRiskEnvelopeWithinLimits(t *testing.T) {
	a := NewAggregateRiskAccounting(time.Hour, 100.0)
	a.RegisterEnvelope(&RiskEnvelope{ActionType: "deploy", MaxRisk: 50.0, Weight: 2.0, Level: RiskHigh})

	err := a.CheckAndRecord("deploy", 25.0)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRiskEnvelopePerActionExceeded(t *testing.T) {
	a := NewAggregateRiskAccounting(time.Hour, 1000.0)
	a.RegisterEnvelope(&RiskEnvelope{ActionType: "deploy", MaxRisk: 10.0, Weight: 1.0})

	err := a.CheckAndRecord("deploy", 15.0)
	if err == nil {
		t.Fatal("expected per-action envelope exceeded")
	}
}

func TestRiskEnvelopeAggregateExceeded(t *testing.T) {
	a := NewAggregateRiskAccounting(time.Hour, 50.0)
	a.RegisterEnvelope(&RiskEnvelope{ActionType: "deploy", MaxRisk: 100.0, Weight: 1.0})

	a.CheckAndRecord("deploy", 30.0)
	err := a.CheckAndRecord("deploy", 25.0)
	if err == nil {
		t.Fatal("expected aggregate exceeded")
	}
}

func TestRiskEnvelopeAntiGaming(t *testing.T) {
	// Weight=3 means risk is multiplied, preventing gaming by splitting into small actions
	a := NewAggregateRiskAccounting(time.Hour, 100.0)
	a.RegisterEnvelope(&RiskEnvelope{ActionType: "high-risk", MaxRisk: 50.0, Weight: 3.0})

	a.CheckAndRecord("high-risk", 10.0)        // weighted: 30
	a.CheckAndRecord("high-risk", 10.0)        // weighted: 30 → total 60
	err := a.CheckAndRecord("high-risk", 10.0) // weighted: 30 → total 90
	if err != nil {
		t.Fatal("expected this to fit: 90 < 100")
	}
	err = a.CheckAndRecord("high-risk", 10.0) // weighted: 30 → total 120
	if err == nil {
		t.Fatal("expected aggregate exceeded via weighting")
	}
}

func TestRiskEnvelopeCurrentAggregate(t *testing.T) {
	a := NewAggregateRiskAccounting(time.Hour, 100.0)
	a.CheckAndRecord("generic", 20.0)

	agg := a.CurrentAggregate()
	if agg != 20.0 {
		t.Fatalf("expected 20.0, got %.2f", agg)
	}
}

func TestRiskEnvelopeSnapshot(t *testing.T) {
	a := NewAggregateRiskAccounting(time.Hour, 100.0)
	hash := a.Snapshot()
	if hash == "" {
		t.Fatal("expected snapshot hash")
	}
}
