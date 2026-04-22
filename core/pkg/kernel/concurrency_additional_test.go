package kernel

import (
	"testing"
)

func TestValidateConcurrencyArtifactDependencyGraph(t *testing.T) {
	// Nil dependency graph
	artifact := &ConcurrencyArtifact{
		Type: ConcurrencyArtifactDependencyGraph,
	}
	issues := ValidateConcurrencyArtifact(artifact)
	if len(issues) == 0 {
		t.Error("Should report nil dependency_graph")
	}

	// Missing hash
	artifact.DependencyGraph = &DependencyGraph{}
	issues = ValidateConcurrencyArtifact(artifact)
	if len(issues) == 0 {
		t.Error("Should report missing hash")
	}

	// Valid
	artifact.DependencyGraph.Hash = "abc123"
	issues = ValidateConcurrencyArtifact(artifact)
	if len(issues) != 0 {
		t.Errorf("Should be valid, got issues: %v", issues)
	}
}

func TestValidateConcurrencyArtifactAttemptIndex(t *testing.T) {
	// Nil attempt index
	artifact := &ConcurrencyArtifact{
		Type: ConcurrencyArtifactAttemptIndex,
	}
	issues := ValidateConcurrencyArtifact(artifact)
	if len(issues) == 0 {
		t.Error("Should report nil attempt_index")
	}

	// Valid
	artifact.AttemptIndex = &AttemptIndex{}
	issues = ValidateConcurrencyArtifact(artifact)
	if len(issues) != 0 {
		t.Errorf("Should be valid, got issues: %v", issues)
	}
}

func TestValidateConcurrencyArtifactRetrySchedule(t *testing.T) {
	// Nil retry schedule
	artifact := &ConcurrencyArtifact{
		Type: ConcurrencyArtifactRetrySchedule,
	}
	issues := ValidateConcurrencyArtifact(artifact)
	if len(issues) == 0 {
		t.Error("Should report nil retry_schedule")
	}

	// Valid
	artifact.RetrySchedule = &RetrySchedule{}
	issues = ValidateConcurrencyArtifact(artifact)
	if len(issues) != 0 {
		t.Errorf("Should be valid, got issues: %v", issues)
	}
}

func TestValidateConcurrencyArtifactExecutionTrace(t *testing.T) {
	// Nil execution trace
	artifact := &ConcurrencyArtifact{
		Type: ConcurrencyArtifactExecutionTrace,
	}
	issues := ValidateConcurrencyArtifact(artifact)
	if len(issues) == 0 {
		t.Error("Should report nil execution_trace")
	}

	// Valid
	artifact.ExecutionTrace = &ExecutionTrace{}
	issues = ValidateConcurrencyArtifact(artifact)
	if len(issues) != 0 {
		t.Errorf("Should be valid, got issues: %v", issues)
	}
}

func TestValidateConcurrencyArtifactUnknownType(t *testing.T) {
	artifact := &ConcurrencyArtifact{
		Type: "UNKNOWN",
	}
	issues := ValidateConcurrencyArtifact(artifact)
	if len(issues) == 0 {
		t.Error("Should report unknown type")
	}
}

func TestAttemptIndexLastAttempt(t *testing.T) {
	index := NewAttemptIndex("idx-1", "op-1", 3)

	// No attempts
	if index.LastAttempt() != nil {
		t.Error("Should return nil when no attempts")
	}

	// After recording
	index.RecordAttempt(false, "E1", "error msg")
	last := index.LastAttempt()
	if last == nil {
		t.Fatal("Should return last attempt")
	}
	if last.Success {
		t.Error("Should be failure")
	}

	// Record another
	index.RecordAttempt(true, "", "")
	last = index.LastAttempt()
	if !last.Success {
		t.Error("Should be success")
	}
}

func TestNormalizeDecimalEdgeCases(t *testing.T) {
	// Test various edge cases for NormalizeDecimal
	tests := []struct {
		input    string
		scale    int
		rounding DecimalRounding
		wantErr  bool
	}{
		{"10.5", 2, DecimalRoundingHalfUp, false},
		{"10.555", 2, DecimalRoundingHalfEven, false},
		{"10", 2, DecimalRoundingDown, false},
		{"-0.00", 2, DecimalRoundingDown, false},
		{"invalid", 2, DecimalRoundingDown, true},
	}

	for _, tt := range tests {
		schema := DecimalSchema{
			Scale:    tt.scale,
			Rounding: tt.rounding,
		}
		_, err := NormalizeDecimal(tt.input, schema)
		if tt.wantErr && err == nil {
			t.Errorf("NormalizeDecimal(%q) should error", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("NormalizeDecimal(%q) error: %v", tt.input, err)
		}
	}
}

func TestCSNFMoneyToDecimal(t *testing.T) {
	money, err := NewMoney(1234, "USD", MoneyPeriod{Kind: PeriodKindInstant})
	if err != nil {
		t.Fatalf("NewMoney error: %v", err)
	}

	dec := money.ToDecimal()
	if dec != "12.34" {
		t.Errorf("ToDecimal = %q, want 12.34", dec)
	}

	// JPY (0 minor units)
	moneyJpy, _ := NewMoney(1000, "JPY", MoneyPeriod{Kind: PeriodKindInstant})
	decJpy := moneyJpy.ToDecimal()
	if decJpy != "1000" {
		t.Errorf("ToDecimal JPY = %q, want 1000", decJpy)
	}
}

func TestMoneyFromDecimalEdgeCases(t *testing.T) {
	// Valid case
	money, err := MoneyFromDecimal("10.50", "USD", MoneyPeriod{Kind: PeriodKindDay})
	if err != nil {
		t.Fatalf("MoneyFromDecimal error: %v", err)
	}
	if money.AmountMinorUnits != 1050 {
		t.Errorf("AmountMinorUnits = %d, want 1050", money.AmountMinorUnits)
	}

	// Invalid decimal
	_, err = MoneyFromDecimal("invalid", "USD", MoneyPeriod{Kind: PeriodKindDay})
	if err == nil {
		t.Error("Should error on invalid decimal")
	}
}
