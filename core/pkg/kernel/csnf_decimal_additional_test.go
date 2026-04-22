package kernel

import (
	"testing"
)

func TestNormalizeDecimalMinBound(t *testing.T) {
	schema := DecimalSchema{
		Scale:    2,
		Rounding: DecimalRoundingHalfUp,
		MinValue: "10.00",
	}

	// Below minimum
	_, err := NormalizeDecimal("5.00", schema)
	if err == nil {
		t.Error("Should error when below minimum")
	}

	// At minimum
	result, err := NormalizeDecimal("10.00", schema)
	if err != nil {
		t.Fatalf("Should accept at minimum: %v", err)
	}
	if result != "10.00" {
		t.Errorf("Got %q, want 10.00", result)
	}

	// Above minimum
	result, err = NormalizeDecimal("15.00", schema)
	if err != nil {
		t.Fatalf("Should accept above minimum: %v", err)
	}
	if result != "15.00" {
		t.Errorf("Got %q, want 15.00", result)
	}
}

func TestNormalizeDecimalMaxBound(t *testing.T) {
	schema := DecimalSchema{
		Scale:    2,
		Rounding: DecimalRoundingHalfUp,
		MaxValue: "100.00",
	}

	// Above maximum
	_, err := NormalizeDecimal("150.00", schema)
	if err == nil {
		t.Error("Should error when above maximum")
	}

	// At maximum
	result, err := NormalizeDecimal("100.00", schema)
	if err != nil {
		t.Fatalf("Should accept at maximum: %v", err)
	}
	if result != "100.00" {
		t.Errorf("Got %q, want 100.00", result)
	}
}

func TestNormalizeDecimalMinMaxBounds(t *testing.T) {
	schema := DecimalSchema{
		Scale:    2,
		Rounding: DecimalRoundingDown,
		MinValue: "0.00",
		MaxValue: "1000.00",
	}

	// Valid in range
	result, err := NormalizeDecimal("500.00", schema)
	if err != nil {
		t.Fatalf("Should accept within range: %v", err)
	}
	if result != "500.00" {
		t.Errorf("Got %q, want 500.00", result)
	}
}

func TestNormalizeDecimalRoundingModes(t *testing.T) {
	tests := []struct {
		input    string
		rounding DecimalRounding
		expected string
	}{
		{"10.555", DecimalRoundingDown, "10.55"},
		{"10.555", DecimalRoundingHalfUp, "10.56"},
		{"10.565", DecimalRoundingHalfEven, "10.56"},
		{"10.575", DecimalRoundingHalfEven, "10.58"},
	}

	for _, tt := range tests {
		schema := DecimalSchema{
			Scale:    2,
			Rounding: tt.rounding,
		}
		result, err := NormalizeDecimal(tt.input, schema)
		if err != nil {
			t.Errorf("NormalizeDecimal(%q, %s) error: %v", tt.input, tt.rounding, err)
			continue
		}
		if result != tt.expected {
			t.Errorf("NormalizeDecimal(%q, %s) = %q, want %q", tt.input, tt.rounding, result, tt.expected)
		}
	}
}

func TestNormalizeDecimalInvalidInput(t *testing.T) {
	schema := DecimalSchema{
		Scale:    2,
		Rounding: DecimalRoundingHalfUp,
	}

	// Invalid decimal
	_, err := NormalizeDecimal("abc", schema)
	if err == nil {
		t.Error("Should error on invalid decimal")
	}

	// Empty string
	_, err = NormalizeDecimal("", schema)
	if err == nil {
		t.Error("Should error on empty string")
	}
}

func TestNormalizeDecimalScaleUp(t *testing.T) {
	schema := DecimalSchema{
		Scale:    4,
		Rounding: DecimalRoundingHalfUp,
	}

	// Integer to 4 decimal places
	result, err := NormalizeDecimal("10", schema)
	if err != nil {
		t.Fatalf("Scale up error: %v", err)
	}
	if result != "10.0000" {
		t.Errorf("Got %q, want 10.0000", result)
	}
}

func TestNormalizeDecimalNegativeZeroHandling(t *testing.T) {
	schema := DecimalSchema{
		Scale:    2,
		Rounding: DecimalRoundingDown,
	}

	// -0.00 should become 0.00
	result, err := NormalizeDecimal("-0.00", schema)
	if err != nil {
		t.Fatalf("Negative zero error: %v", err)
	}
	if result != "0.00" {
		t.Errorf("Got %q, want 0.00", result)
	}
}

func TestMoneyFromDecimalInvalidCases(t *testing.T) {
	period := MoneyPeriod{Kind: PeriodKindInstant}

	// Invalid decimal format
	_, err := MoneyFromDecimal("not-a-number", "USD", period)
	if err == nil {
		t.Error("Should error on invalid decimal format")
	}
}

func TestToDecimalDifferentCurrencies(t *testing.T) {
	// US Dollars (2 minor units)
	usd, _ := NewMoney(12345, "USD", MoneyPeriod{Kind: PeriodKindInstant})
	if usd.ToDecimal() != "123.45" {
		t.Errorf("USD ToDecimal = %q, want 123.45", usd.ToDecimal())
	}

	// Japanese Yen (0 minor units)
	jpy, _ := NewMoney(12345, "JPY", MoneyPeriod{Kind: PeriodKindInstant})
	if jpy.ToDecimal() != "12345" {
		t.Errorf("JPY ToDecimal = %q, want 12345", jpy.ToDecimal())
	}

	// Kuwaiti Dinar (3 minor units)
	kwd, _ := NewMoney(12345, "KWD", MoneyPeriod{Kind: PeriodKindInstant})
	if kwd.ToDecimal() != "12.345" {
		t.Errorf("KWD ToDecimal = %q, want 12.345", kwd.ToDecimal())
	}
}

func TestValidateMoneyIssues(t *testing.T) {
	// Invalid currency
	m1 := &CSNFMoney{
		AmountMinorUnits: 1000,
		Currency:         "",
		Period:           MoneyPeriod{Kind: PeriodKindInstant},
	}
	issues := ValidateMoney(m1)
	if len(issues) == 0 {
		t.Error("Should report empty currency")
	}

	// Invalid period kind
	m2 := &CSNFMoney{
		AmountMinorUnits: 1000,
		Currency:         "USD",
		Period:           MoneyPeriod{Kind: "INVALID"},
	}
	issues = ValidateMoney(m2)
	if len(issues) == 0 {
		t.Error("Should report invalid period kind")
	}
}
