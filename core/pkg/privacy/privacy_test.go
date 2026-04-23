package privacy

import (
	"context"
	"testing"
)

func TestStandardPrivacyManager_Scrub(t *testing.T) {
	pm := NewPrivacyManager()
	ctx := context.Background()

	tests := []struct {
		name  string
		input string
		level PIIClassification
		want  string
	}{
		{
			name:  "No PII",
			input: "Hello World",
			level: PIINone,
			want:  "Hello World",
		},
		{
			name:  "Email Redaction Sensitive",
			input: "Contact me at user@example.com",
			level: PIISensitive,
			want:  "Contact me at [REDACTED_EMAIL]",
		},
		{
			name:  "Email Redaction Critical",
			input: "Contact me at user@example.com",
			level: PIICritical,
			want:  "Contact me at [REDACTED_EMAIL]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pm.Scrub(ctx, tt.input, tt.level); got != tt.want {
				t.Errorf("StandardPrivacyManager.Scrub() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStandardPrivacyManager_Validate(t *testing.T) {
	pm := NewPrivacyManager()
	ctx := context.Background()

	tests := []struct {
		name           string
		data           map[string]interface{}
		wantValid      bool
		wantViolations int
	}{
		{
			name: "Valid Data",
			data: map[string]interface{}{
				"username": "jdoe",
				"age":      30,
			},
			wantValid:      true,
			wantViolations: 0,
		},
		{
			name: "Invalid KEY SSN",
			data: map[string]interface{}{
				"username": "jdoe",
				"ssn":      "123-45-6789",
			},
			wantValid:      false,
			wantViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, violations := pm.Validate(ctx, tt.data)
			if valid != tt.wantValid {
				t.Errorf("StandardPrivacyManager.Validate() valid = %v, want %v", valid, tt.wantValid)
			}
			if len(violations) != tt.wantViolations {
				t.Errorf("StandardPrivacyManager.Validate() violations count = %v, want %v", len(violations), tt.wantViolations)
			}
		})
	}
}
