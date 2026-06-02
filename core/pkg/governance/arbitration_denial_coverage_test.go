package governance

import (
	"testing"
	"time"
)

func TestArbitrateFallbackAndTieBreakBranches(t *testing.T) {
	inputs := []ArbitrationInput{
		{RuleID: "allow-rule-a", Decision: "ALLOW"},
		{RuleID: "allow-rule-b", Decision: "ALLOW"},
	}
	record := Arbitrate(inputs, "UNKNOWN")
	if record == nil {
		t.Fatal("expected fallback arbitration record")
	}
	if record.Strategy != StrategyStrictest {
		t.Fatalf("Strategy=%s want %s", record.Strategy, StrategyStrictest)
	}
	if record.RuleBID != "allow-rule-b" {
		t.Fatalf("RuleBID=%q want allow-rule-b", record.RuleBID)
	}

	escalated := Arbitrate([]ArbitrationInput{
		{RuleID: "low-priority", Decision: "ALLOW", Priority: 1},
		{RuleID: "high-priority", Decision: "DENY", Priority: 10},
	}, StrategyEscalate)
	if escalated.RuleAID != "high-priority" {
		t.Fatalf("RuleAID=%q want high-priority", escalated.RuleAID)
	}
}

func TestDenialLedgerWithClock(t *testing.T) {
	ts := time.Date(2026, 6, 2, 12, 30, 0, 0, time.UTC)
	ledger := NewDenialLedger().WithClock(func() time.Time { return ts })

	receipt := ledger.Deny("agent-1", "deploy", DenialPolicy, "blocked")
	if !receipt.DeniedAt.Equal(ts) {
		t.Fatalf("DeniedAt=%v want %v", receipt.DeniedAt, ts)
	}
}
