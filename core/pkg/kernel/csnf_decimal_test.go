package kernel

import (
	"testing"
)

//nolint:gocognit // test complexity is acceptable
func TestParseDecimal(t *testing.T) {
	t.Run("Valid decimals", func(t *testing.T) {
		validInputs := []string{
			"123.45",
			"-123.45",
			"0.0",
			"1",
			"-1",
			"123456789.123456789",
			"0",
			"+12.34",
		}

		for _, input := range validInputs {
			d, err := ParseDecimal(input)
			if err != nil {
				t.Errorf("ParseDecimal(%q) failed: %v", input, err)
			}
			if d == nil {
				t.Errorf("ParseDecimal(%q) returned nil without error", input)
			}
		}
	})

	t.Run("Invalid decimals", func(t *testing.T) {
		invalids := []string{"abc", "12.34.56", "", "12a34", ".5", "5."}
		for _, s := range invalids {
			_, err := ParseDecimal(s)
			if err == nil {
				t.Errorf("ParseDecimal(%q) should fail", s)
			}
		}
	})

	t.Run("Negative zero normalization", func(t *testing.T) {
		inputs := []string{"-0", "-0.0", "-0.00"}
		for _, input := range inputs {
			d, err := ParseDecimal(input)
			if err != nil {
				t.Errorf("ParseDecimal(%q) failed: %v", input, err)
				continue
			}
			// After normalization, should not have leading minus for zero
			if d.Value[0] == '-' {
				t.Errorf("ParseDecimal(%q) = %q, expected positive zero", input, d.Value)
			}
		}
	})
}

func TestNormalizeDecimal(t *testing.T) {
	schema := DecimalSchema{
		Scale:    2,
		Rounding: DecimalRoundingHalfUp,
	}

	t.Run("Normalize valid decimals", func(t *testing.T) {
		tests := []string{"123.456", "1", "0.1", "-5.555"}

		for _, input := range tests {
			result, err := NormalizeDecimal(input, schema)
			if err != nil {
				t.Errorf("NormalizeDecimal(%q) failed: %v", input, err)
				continue
			}
			t.Logf("NormalizeDecimal(%q) = %q", input, result)
		}
	})

	t.Run("Invalid input", func(t *testing.T) {
		_, err := NormalizeDecimal("invalid", schema)
		if err == nil {
			t.Error("Expected error for invalid input")
		}
	})
}

//nolint:gocognit // test complexity is acceptable
func TestCSNFMoney(t *testing.T) {
	period := MoneyPeriod{Kind: PeriodKindInstant}

	t.Run("NewMoney", func(t *testing.T) {
		m, err := NewMoney(1234, "USD", period)
		if err != nil {
			t.Fatalf("NewMoney failed: %v", err)
		}
		if m.AmountMinorUnits != 1234 {
			t.Errorf("AmountMinorUnits = %d, want 1234", m.AmountMinorUnits)
		}
		if m.Currency != "USD" {
			t.Errorf("Currency = %q, want USD", m.Currency)
		}
	})

	t.Run("NewMoney with invalid currency", func(t *testing.T) {
		_, err := NewMoney(1234, "TOOLONG", period)
		if err == nil {
			t.Error("Expected error for invalid currency length")
		}
	})

	t.Run("NewMoney with custom period without ID", func(t *testing.T) {
		customPeriod := MoneyPeriod{Kind: PeriodKindCustom}
		_, err := NewMoney(1234, "USD", customPeriod)
		if err == nil {
			t.Error("Expected error for custom period without ID")
		}
	})

	t.Run("NewMoney with custom period with ID", func(t *testing.T) {
		customPeriod := MoneyPeriod{Kind: PeriodKindCustom, ID: "fiscal-q1"}
		m, err := NewMoney(1234, "USD", customPeriod)
		if err != nil {
			t.Fatalf("NewMoney failed: %v", err)
		}
		if m.Period.ID != "fiscal-q1" {
			t.Errorf("Period.ID = %q, want fiscal-q1", m.Period.ID)
		}
	})

	t.Run("MoneyFromDecimal", func(t *testing.T) {
		m, err := MoneyFromDecimal("12.34", "USD", period)
		if err != nil {
			t.Fatalf("MoneyFromDecimal failed: %v", err)
		}
		if m.AmountMinorUnits != 1234 {
			t.Errorf("AmountMinorUnits = %d, want 1234", m.AmountMinorUnits)
		}
	})

	t.Run("MoneyFromDecimal JPY", func(t *testing.T) {
		// JPY has 0 minor units
		m, err := MoneyFromDecimal("1234", "JPY", period)
		if err != nil {
			t.Fatalf("MoneyFromDecimal failed: %v", err)
		}
		if m.AmountMinorUnits != 1234 {
			t.Errorf("AmountMinorUnits = %d, want 1234", m.AmountMinorUnits)
		}
	})

	t.Run("CSNFMoney.ToDecimal", func(t *testing.T) {
		m := &CSNFMoney{AmountMinorUnits: 1234, Currency: "USD", Period: period}
		d := m.ToDecimal()
		if d != "12.34" {
			t.Errorf("ToDecimal() = %q, want 12.34", d)
		}
	})

	t.Run("ValidateMoney", func(t *testing.T) {
		valid := &CSNFMoney{AmountMinorUnits: 100, Currency: "USD", Period: period}
		errs := ValidateMoney(valid)
		if len(errs) > 0 {
			t.Errorf("ValidateMoney failed for valid money: %v", errs)
		}

		invalid := &CSNFMoney{AmountMinorUnits: 100, Currency: ""}
		errs = ValidateMoney(invalid)
		if len(errs) == 0 {
			t.Error("Expected errors for invalid money with empty currency")
		}
	})

	t.Run("CurrencyMinorUnits", func(t *testing.T) {
		tests := []struct {
			currency string
			expected int
		}{
			{"USD", 2},
			{"EUR", 2},
			{"JPY", 0},
			{"BHD", 3},
			{"UNKNOWN", 2}, // Default
		}

		for _, tc := range tests {
			units := CurrencyMinorUnits(tc.currency)
			if units != tc.expected {
				t.Errorf("CurrencyMinorUnits(%q) = %d, want %d", tc.currency, units, tc.expected)
			}
		}
	})
}

func TestIsAllZeros(t *testing.T) {
	if !isAllZeros("0000") {
		t.Error("Expected true for all zeros")
	}
	if isAllZeros("0010") {
		t.Error("Expected false for non-zero")
	}
	if !isAllZeros("") {
		t.Error("Expected true for empty string")
	}
}

func TestNormalizeNegativeZero(t *testing.T) {
	t.Run("Negative zero to zero", func(t *testing.T) {
		result := normalizeNegativeZero("-0")
		if result != "0" {
			t.Errorf("Expected '0', got %q", result)
		}

		result = normalizeNegativeZero("-0.0")
		if result != "0.0" {
			t.Errorf("Expected '0.0', got %q", result)
		}
	})

	t.Run("Non-zero preserved", func(t *testing.T) {
		result := normalizeNegativeZero("-1")
		if result != "-1" {
			t.Errorf("Expected '-1', got %q", result)
		}

		result = normalizeNegativeZero("-0.5")
		if result != "-0.5" {
			t.Errorf("Expected '-0.5', got %q", result)
		}
	})
}
