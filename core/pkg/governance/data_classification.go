package governance

import (
	"regexp"
	"strings"
)

// DataClass represents the sensitivity level of data.
type DataClass string

const (
	DataClassPublic       DataClass = "PUBLIC"       // Freely shareable
	DataClassInternal     DataClass = "INTERNAL"     // Default, company wide
	DataClassConfidential DataClass = "CONFIDENTIAL" // Need to know (PII, Secrets)
	DataClassRestricted   DataClass = "RESTRICTED"   // Core infrastructure, break-glass only
)

// DataObject is an interface for anything that carries data classification.
type DataObject interface {
	GetClassification() DataClass
}

// Classifier provides heuristic-based data classification.
type Classifier struct {
	piiPatterns []*regexp.Regexp
}

func NewClassifier() *Classifier {
	return &Classifier{
		piiPatterns: []*regexp.Regexp{
			// Simple email regex
			regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			// Simple SSN / ID regex (placeholder)
			regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			// API Key-like strings (high entropy, "sk-...")
			regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
		},
	}
}

// Classify determines the sensitivity of a text buffer.
func (c *Classifier) Classify(content string) DataClass {
	// 1. Check for Restricted keywords
	if strings.Contains(content, "root_password") || strings.Contains(content, "-----BEGIN PRIVATE KEY-----") {
		return DataClassRestricted
	}

	// 2. Check for Confidential patterns (PII, API Keys)
	for _, p := range c.piiPatterns {
		if p.MatchString(content) {
			return DataClassConfidential
		}
	}

	// 3. Default to Internal
	// (Public requires explicit tagging usually, but for auto-classification we assume Internal)
	return DataClassInternal
}
