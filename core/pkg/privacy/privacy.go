package privacy

import (
	"context"
	"regexp"
)

// PIIClassification defines the sensitivity level of data.
type PIIClassification string

const (
	PIINone      PIIClassification = "NONE"
	PIISensitive PIIClassification = "SENSITIVE" // Name, Email, IP, etc.
	PIICritical  PIIClassification = "CRITICAL"  // SSN, Credit Card, Health Data
)

// PrivacyManager defines the interface for privacy controls.
type PrivacyManager interface {
	// Scrub removes PII from the given text based on the classification.
	Scrub(ctx context.Context, text string, level PIIClassification) string
	// Validate verifies if the data complies with privacy policies.
	Validate(ctx context.Context, data map[string]interface{}) (bool, []string)
}

// StandardPrivacyManager implements the PrivacyManager interface.
type StandardPrivacyManager struct {
	emailRegex *regexp.Regexp
}

// NewPrivacyManager returns a new instance of StandardPrivacyManager.
func NewPrivacyManager() *StandardPrivacyManager {
	return &StandardPrivacyManager{
		emailRegex: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	}
}

// Scrub redacts PII from the text.
func (pm *StandardPrivacyManager) Scrub(ctx context.Context, text string, level PIIClassification) string {
	if level == PIINone {
		return text
	}

	// Simple redaction for emails as a proof of concept
	return pm.emailRegex.ReplaceAllString(text, "[REDACTED_EMAIL]")
}

// Validate checks for privacy compliance.
// For now, it just ensures no critical PII keys exist in the top level of the map.
func (pm *StandardPrivacyManager) Validate(ctx context.Context, data map[string]interface{}) (bool, []string) {
	var violations []string
	// Example rule: no key should contain "ssn" or "credit_card"
	restrictedKeys := []string{"ssn", "social_security", "credit_card", "cc_number"}

	for key := range data {
		for _, restricted := range restrictedKeys {
			if key == restricted {
				violations = append(violations, "found restricted key: "+key)
			}
		}
	}

	if len(violations) > 0 {
		return false, violations
	}
	return true, nil
}
