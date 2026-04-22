// Package kernel provides Decimal and Money profiles for CSNF.
// Per HELM Normative Addendum v1.5 Section A.5 and A.6.
package kernel

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// CSNFDecimalProfileID is the profile identifier for decimal handling.
const CSNFDecimalProfileID = "csnf-decimal-v1"

// CSNFMoneyProfileID is the profile identifier for money handling.
const CSNFMoneyProfileID = "csnf-money-v1"

// DecimalRounding defines rounding modes for decimal normalization.
type DecimalRounding string

const (
	DecimalRoundingDown     DecimalRounding = "DOWN"
	DecimalRoundingHalfUp   DecimalRounding = "HALF_UP"
	DecimalRoundingHalfEven DecimalRounding = "HALF_EVEN"
)

// decimalPattern matches valid decimal strings per Section A.5.
// ^[+-]?[0-9]+(\.[0-9]+)?$
var decimalPattern = regexp.MustCompile(`^[+-]?[0-9]+(\.[0-9]+)?$`)

// CSNFDecimal represents a decimal value in CSNF-compliant format.
// Per Section A.5: Represented as strings with explicit rules.
type CSNFDecimal struct {
	Value string `json:"value"`
}

// DecimalSchema defines the schema constraints for a decimal field.
type DecimalSchema struct {
	Scale    int             `json:"x-decimal-scale"`    // Max fractional digits
	Rounding DecimalRounding `json:"x-decimal-rounding"` // Rounding mode
	MinValue string          `json:"x-decimal-min,omitempty"`
	MaxValue string          `json:"x-decimal-max,omitempty"`
}

// ParseDecimal parses and validates a decimal string.
func ParseDecimal(s string) (*CSNFDecimal, error) {
	if !decimalPattern.MatchString(s) {
		return nil, fmt.Errorf("csnf-decimal: invalid format %q (must match ^[+-]?[0-9]+(\\.[0-9]+)?$)", s)
	}

	// Normalize negative zero
	if s == "-0" || s == "-0.0" || strings.HasPrefix(s, "-0.") && isAllZeros(s[3:]) {
		s = normalizeNegativeZero(s)
	}

	return &CSNFDecimal{Value: s}, nil
}

// isAllZeros checks if a string contains only zeros.
func isAllZeros(s string) bool {
	for _, c := range s {
		if c != '0' {
			return false
		}
	}
	return true
}

// normalizeNegativeZero converts negative zero to positive zero.
func normalizeNegativeZero(s string) string {
	if strings.HasPrefix(s, "-") {
		// Check if value is zero
		rest := s[1:]
		if rest == "0" {
			return "0"
		}
		if strings.HasPrefix(rest, "0.") && isAllZeros(rest[2:]) {
			return rest // Remove minus sign
		}
	}
	return s
}

// NormalizeDecimal normalizes a decimal to the specified scale.
// Per Section A.5: Normalized to exactly the declared scale.
func NormalizeDecimal(s string, schema DecimalSchema) (string, error) {
	d, err := ParseDecimal(s)
	if err != nil {
		return "", err
	}

	// Use big.Rat for precise decimal arithmetic
	rat := new(big.Rat)
	if _, ok := rat.SetString(d.Value); !ok {
		return "", fmt.Errorf("csnf-decimal: could not parse %q as rational", d.Value)
	}

	// Check bounds
	if schema.MinValue != "" {
		minRat := new(big.Rat)
		if _, ok := minRat.SetString(schema.MinValue); ok {
			if rat.Cmp(minRat) < 0 {
				return "", fmt.Errorf("csnf-decimal: %s < minimum %s", s, schema.MinValue)
			}
		}
	}
	if schema.MaxValue != "" {
		maxRat := new(big.Rat)
		if _, ok := maxRat.SetString(schema.MaxValue); ok {
			if rat.Cmp(maxRat) > 0 {
				return "", fmt.Errorf("csnf-decimal: %s > maximum %s", s, schema.MaxValue)
			}
		}
	}

	// Apply rounding and scale
	return formatDecimal(rat, schema.Scale, schema.Rounding), nil
}

// formatDecimal formats a rational to the specified scale with rounding.
func formatDecimal(rat *big.Rat, scale int, rounding DecimalRounding) string {
	// Multiply by 10^scale to get integer representation
	scaleFactor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)
	scaled := new(big.Rat).Mul(rat, new(big.Rat).SetInt(scaleFactor))

	// Get integer and remainder for rounding
	intPart := new(big.Int).Div(scaled.Num(), scaled.Denom())
	remainder := new(big.Int).Mod(scaled.Num(), scaled.Denom())

	// Apply rounding
	if remainder.Sign() != 0 {
		halfDenom := new(big.Int).Div(scaled.Denom(), big.NewInt(2))

		switch rounding {
		case DecimalRoundingDown:
			// Truncate - do nothing
		case DecimalRoundingHalfUp:
			if remainder.Cmp(halfDenom) >= 0 {
				intPart.Add(intPart, big.NewInt(1))
			}
		case DecimalRoundingHalfEven:
			cmp := remainder.Cmp(halfDenom)
			if cmp > 0 {
				intPart.Add(intPart, big.NewInt(1))
			} else if cmp == 0 {
				// Round to even
				if new(big.Int).And(intPart, big.NewInt(1)).Sign() != 0 {
					intPart.Add(intPart, big.NewInt(1))
				}
			}
		}
	}

	// Format with scale
	if scale == 0 {
		return intPart.String()
	}

	// Handle negative values
	sign := ""
	if intPart.Sign() < 0 {
		sign = "-"
		intPart.Abs(intPart)
	}

	// Pad to ensure enough digits for fractional part
	intStr := intPart.String()
	for len(intStr) <= scale {
		intStr = "0" + intStr
	}

	insertPoint := len(intStr) - scale
	return sign + intStr[:insertPoint] + "." + intStr[insertPoint:]
}

// PeriodKind defines the kind of measurement period for money.
type PeriodKind string

const (
	PeriodKindInstant  PeriodKind = "INSTANT"
	PeriodKindDay      PeriodKind = "DAY"
	PeriodKindMonth    PeriodKind = "MONTH"
	PeriodKindInvoice  PeriodKind = "INVOICE"
	PeriodKindContract PeriodKind = "CONTRACT"
	PeriodKindCustom   PeriodKind = "CUSTOM"
)

// MoneyPeriod defines the measurement period for a money value.
type MoneyPeriod struct {
	Kind PeriodKind `json:"kind"`
	ID   string     `json:"id,omitempty"` // Required for CUSTOM kind
}

// CSNFMoney represents a monetary value in CSNF-compliant format.
// Per Section A.6: Money represented as minor units with currency and period.
type CSNFMoney struct {
	AmountMinorUnits int64       `json:"amount_minor_units"`
	Currency         string      `json:"currency"` // ISO 4217 code
	Period           MoneyPeriod `json:"period"`
}

// NewMoney creates a new money value.
func NewMoney(amountMinorUnits int64, currency string, period MoneyPeriod) (*CSNFMoney, error) {
	// Validate currency code (ISO 4217 format)
	if len(currency) != 3 {
		return nil, fmt.Errorf("csnf-money: currency must be 3-letter ISO 4217 code, got %q", currency)
	}

	// Validate period
	if period.Kind == PeriodKindCustom && period.ID == "" {
		return nil, fmt.Errorf("csnf-money: CUSTOM period requires id")
	}

	return &CSNFMoney{
		AmountMinorUnits: amountMinorUnits,
		Currency:         strings.ToUpper(currency),
		Period:           period,
	}, nil
}

// MoneyFromDecimal creates a Money from a decimal string and currency.
// Uses the currency's standard minor unit scale (e.g., 2 for USD, 0 for JPY).
func MoneyFromDecimal(decimalAmount, currency string, period MoneyPeriod) (*CSNFMoney, error) {
	scale := CurrencyMinorUnits(currency)

	d, err := ParseDecimal(decimalAmount)
	if err != nil {
		return nil, err
	}

	// Parse to rational
	rat := new(big.Rat)
	if _, ok := rat.SetString(d.Value); !ok {
		return nil, fmt.Errorf("csnf-money: could not parse decimal %q", decimalAmount)
	}

	// Multiply by 10^scale to get minor units
	scaleFactor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)
	scaled := new(big.Rat).Mul(rat, new(big.Rat).SetInt(scaleFactor))

	// Must be exact integer
	if !scaled.IsInt() {
		return nil, fmt.Errorf("csnf-money: %s has more precision than currency %s allows", decimalAmount, currency)
	}

	return NewMoney(scaled.Num().Int64(), currency, period)
}

// ToDecimal converts money to a decimal string.
func (m *CSNFMoney) ToDecimal() string {
	scale := CurrencyMinorUnits(m.Currency)

	if scale == 0 {
		return fmt.Sprintf("%d", m.AmountMinorUnits)
	}

	// Format with decimal point
	sign := ""
	amount := m.AmountMinorUnits
	if amount < 0 {
		sign = "-"
		amount = -amount
	}

	intStr := fmt.Sprintf("%d", amount)
	for len(intStr) <= scale {
		intStr = "0" + intStr
	}

	insertPoint := len(intStr) - scale
	return sign + intStr[:insertPoint] + "." + intStr[insertPoint:]
}

// CurrencyMinorUnits returns the number of minor units for a currency.
// Common currencies; extend as needed.
func CurrencyMinorUnits(currency string) int {
	switch strings.ToUpper(currency) {
	case "JPY", "KRW", "VND": // Zero decimal currencies
		return 0
	case "BHD", "KWD", "OMR": // Three decimal currencies
		return 3
	default: // Most currencies use 2 decimals
		return 2
	}
}

// ValidateMoney validates a money value.
func ValidateMoney(m *CSNFMoney) []string {
	issues := []string{}

	if len(m.Currency) != 3 {
		issues = append(issues, "currency must be 3-letter ISO 4217 code")
	}

	validKinds := map[PeriodKind]bool{
		PeriodKindInstant: true, PeriodKindDay: true, PeriodKindMonth: true,
		PeriodKindInvoice: true, PeriodKindContract: true, PeriodKindCustom: true,
	}
	if !validKinds[m.Period.Kind] {
		issues = append(issues, fmt.Sprintf("invalid period kind: %s", m.Period.Kind))
	}

	if m.Period.Kind == PeriodKindCustom && m.Period.ID == "" {
		issues = append(issues, "CUSTOM period requires id")
	}

	return issues
}
