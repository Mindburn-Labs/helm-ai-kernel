// Package disclosure defines the public contracts for HELM's disclosure and redaction.
//
// Disclosure provides typed policies for controlling what governance data
// can be revealed in different contexts, and redaction rules for sanitizing
// evidence before external sharing.
package disclosure

// DisclosurePolicy defines what can be disclosed in a given context.
type DisclosurePolicy struct {
	PolicyID    string          `json:"policy_id"`
	Name        string          `json:"name"`
	Context     string          `json:"context"` // "AUDIT", "COMPLIANCE", "PUBLIC", "INTERNAL"
	Rules       []DisclosureRule `json:"rules"`
}

// DisclosureRule specifies a single disclosure permission or restriction.
type DisclosureRule struct {
	RuleID   string   `json:"rule_id"`
	Type     string   `json:"type"` // "ALLOW", "DENY", "REDACT"
	Fields   []string `json:"fields"`
	Reason   string   `json:"reason,omitempty"`
}

// RedactionSpec defines how to redact sensitive fields from governance artifacts.
type RedactionSpec struct {
	SpecID       string           `json:"spec_id"`
	TargetType   string           `json:"target_type"` // "RECEIPT", "EVIDENCE_PACK", "PHENOTYPE"
	Redactions   []RedactionRule  `json:"redactions"`
}

// RedactionRule specifies a single redaction operation.
type RedactionRule struct {
	Field      string `json:"field"`      // JSONPath or field name
	Strategy   string `json:"strategy"`   // "HASH", "MASK", "REMOVE", "TRUNCATE"
	Length     int    `json:"length,omitempty"` // For TRUNCATE strategy
	Salt       string `json:"salt,omitempty"`   // For HASH strategy
}

// Redactor is the canonical interface for applying redaction to artifacts.
type Redactor interface {
	Redact(artifact any, spec *RedactionSpec) (any, error)
}
