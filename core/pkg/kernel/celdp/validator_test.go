package celdp

import (
	"strings"
	"testing"
)

func TestValidator(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name      string
		expr      string
		wantValid bool
		wantIssue string // substring match
	}{
		{
			name:      "Valid Integer Math",
			expr:      "1 + 2",
			wantValid: true,
		},
		{
			name:      "Valid String Ops",
			expr:      "'hello'.startsWith('h')",
			wantValid: true,
		},
		{
			name:      "Forbidden Float Literal",
			expr:      "1.5 + 2.0",
			wantValid: false,
			wantIssue: "Floating point literals",
		},
		{
			name:      "Forbidden now()",
			expr:      "now() > timestamp('2023-01-01T00:00:00Z')",
			wantValid: false,
			wantIssue: "now() is forbidden",
		},
		{
			name:      "Forbidden Map Keys",
			expr:      "{'a': 1}.keys()",
			wantValid: false,
			wantIssue: "Map iteration",
		},
		{
			name:      "Forbidden Map Values",
			expr:      "{'a': 1}.values()",
			wantValid: false,
			wantIssue: "Map iteration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := v.Validate(tt.expr)
			if err != nil {
				// Some might be parse errors which we accept as "not valid"?
				// But Validate shouldn't return err for violation, only for internal/parse failure?
				// The implementation returns err on parse failure.
				// If parse failure occurs for a valid syntax (e.g. valid CEL but invalid DP), that's unexpected.
				// But "now()" is valid CEL.
				t.Fatalf("Validate(%q) unexpected error: %v", tt.expr, err)
			}

			if result.Valid != tt.wantValid {
				t.Errorf("Validate(%q) valid = %v, want %v. Issues: %v", tt.expr, result.Valid, tt.wantValid, result.Issues)
			}

			if !tt.wantValid && tt.wantIssue != "" {
				found := false
				for _, iss := range result.Issues {
					if strings.Contains(iss.Message, tt.wantIssue) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Validate(%q) issues %v, expected to contain %q", tt.expr, result.Issues, tt.wantIssue)
				}
			}
		})
	}
}
