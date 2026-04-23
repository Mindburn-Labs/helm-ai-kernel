package kernel

import (
	"testing"
)

func TestIsFloatLiteral(t *testing.T) {
	tests := []struct {
		expr    string
		pattern string
		want    bool
	}{
		{"1.5", ".5", true},      // decimal preceded by digit
		{".5", ".5", false},      // no digit before
		{"double(x)", "(", true}, // type conversion
		{"x + y", "+", false},    // not a float literal
		{"abc", ".5", false},     // pattern not found
	}

	for _, tt := range tests {
		got := isFloatLiteral(tt.expr, tt.pattern)
		if got != tt.want {
			t.Errorf("isFloatLiteral(%q, %q) = %v, want %v", tt.expr, tt.pattern, got, tt.want)
		}
	}
}

func TestFindLocationExtended(t *testing.T) {
	tests := []struct {
		expr    string
		pattern string
		want    string
	}{
		{"hello world", "world", "char 6"},
		{"hello", "world", ""},
		{"abc", "a", "char 0"},
		{"", "x", ""},
	}

	for _, tt := range tests {
		got := findLocation(tt.expr, tt.pattern)
		if got != tt.want {
			t.Errorf("findLocation(%q, %q) = %q, want %q", tt.expr, tt.pattern, got, tt.want)
		}
	}
}

func TestHasErrorsExtended(t *testing.T) {
	// No errors
	issues := []CELDPIssue{
		{Severity: "warning", RuleID: "DP01", Message: "test"},
	}
	if hasErrors(issues) {
		t.Error("Should return false when no errors")
	}

	// Has errors
	issues = append(issues, CELDPIssue{Severity: "error", RuleID: "DP02", Message: "test"})
	if !hasErrors(issues) {
		t.Error("Should return true when has errors")
	}
}

func TestFormatValidationIssuesExtended(t *testing.T) {
	issues := []CELDPIssue{
		{RuleID: "DP01", Message: "message 1"},
		{RuleID: "DP02", Message: "message 2"},
	}

	result := formatValidationIssues(issues)
	if result != "[DP01] message 1; [DP02] message 2" {
		t.Errorf("formatValidationIssues = %q", result)
	}
}
