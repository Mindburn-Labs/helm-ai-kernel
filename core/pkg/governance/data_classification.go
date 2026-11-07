package governance

import (
	"regexp"
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
