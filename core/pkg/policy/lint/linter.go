// Package lint provides static analysis for HELM policy bundles.
// It validates policy structure, detects common mistakes, and warns
// about potential security issues before deployment.
//
// Design invariants:
//   - Linting is offline — no network calls
//   - All checks are deterministic
//   - Findings are classified by severity (ERROR, WARNING, INFO)
//   - ERRORs block deployment; WARNINGs are advisory
//   - Extensible via custom rules
package lint

import (
	"encoding/json"
	"fmt"
)

// Severity classifies the impact of a lint finding.
type Severity string

const (
	// SeverityError indicates a problem that blocks deployment.
	SeverityError Severity = "ERROR"
	// SeverityWarning indicates a potential issue that merits review.
	SeverityWarning Severity = "WARNING"
	// SeverityInfo indicates an informational observation.
	SeverityInfo Severity = "INFO"
)

// Finding represents a single issue discovered during linting.
type Finding struct {
	RuleID     string   `json:"rule_id"`
	Severity   Severity `json:"severity"`
	Message    string   `json:"message"`
	Path       string   `json:"path,omitempty"`       // JSONPath to problematic field
	Suggestion string   `json:"suggestion,omitempty"` // Suggested fix
}

// LintResult aggregates all findings from a lint pass.
type LintResult struct {
	Findings   []Finding `json:"findings"`
	ErrorCount int       `json:"error_count"`
	WarnCount  int       `json:"warn_count"`
	InfoCount  int       `json:"info_count"`
	Valid      bool      `json:"valid"` // True if no ERRORs
}

// Rule defines a single lint check that inspects a policy bundle.
type Rule struct {
	ID       string
	Severity Severity
	Check    func(bundle *PolicyBundle) []Finding
}

// PolicyBundle is the input structure for linting.
// It represents a parsed policy bundle with its metadata and rules.
type PolicyBundle struct {
	Version     string          `json:"version"`
	ID          string          `json:"id"`
	ContentHash string          `json:"content_hash,omitempty"`
	Rules       []PolicyRule    `json:"rules"`
	Metadata    map[string]any  `json:"metadata,omitempty"`
	RawJSON     json.RawMessage `json:"-"` // Original JSON for structural checks
}

// PolicyRule describes a single rule within a policy bundle.
type PolicyRule struct {
	Name       string         `json:"name"`
	Action     string         `json:"action"` // ALLOW, DENY, ESCALATE
	Priority   int            `json:"priority"`
	Conditions map[string]any `json:"conditions,omitempty"`
	Effect     string         `json:"effect,omitempty"`
}

// Linter runs a set of rules against policy bundles.
type Linter struct {
	rules []Rule
}

// Option configures the Linter.
type Option func(*Linter)

// WithRule returns an Option that adds a custom rule to the Linter.
func WithRule(r Rule) Option {
	return func(l *Linter) {
		l.rules = append(l.rules, r)
	}
}

// New creates a Linter with all built-in rules and any additional
// rules supplied via options.
func New(opts ...Option) *Linter {
	l := &Linter{}

	// Register built-in rules in evaluation order.
	l.rules = append(l.rules,
		ruleRequireVersion(),
		ruleRequireID(),
		ruleNonEmptyRules(),
		ruleValidActions(),
		ruleNoDuplicateNames(),
		ruleNoOverlappingPriorities(),
		ruleDenyDefault(),
		ruleContentHashPresent(),
		ruleMaxRuleCount(),
		ruleConditionsNotEmpty(),
	)

	for _, opt := range opts {
		opt(l)
	}
	return l
}

// Lint runs every registered rule against the given bundle and returns
// an aggregated result. The result's Valid field is true only when no
// ERROR-severity findings exist.
func (l *Linter) Lint(bundle *PolicyBundle) *LintResult {
	result := &LintResult{
		Valid: true,
	}

	for _, rule := range l.rules {
		findings := rule.Check(bundle)
		for i := range findings {
			result.Findings = append(result.Findings, findings[i])
			switch findings[i].Severity {
			case SeverityError:
				result.ErrorCount++
				result.Valid = false
			case SeverityWarning:
				result.WarnCount++
			case SeverityInfo:
				result.InfoCount++
			}
		}
	}
	return result
}

// LintJSON parses raw JSON into a PolicyBundle and lints it.
// The original JSON is preserved in RawJSON for structural checks.
func (l *Linter) LintJSON(data []byte) (*LintResult, error) {
	var bundle PolicyBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("lint: failed to parse policy bundle JSON: %w", err)
	}
	bundle.RawJSON = data
	return l.Lint(&bundle), nil
}

// ---------------------------------------------------------------------------
// Built-in rules
// ---------------------------------------------------------------------------

// validActions is the set of recognised CPI verdicts.
var validActions = map[string]bool{
	"ALLOW":    true,
	"DENY":     true,
	"ESCALATE": true,
}

// ruleRequireVersion returns a Rule that errors when version is empty.
func ruleRequireVersion() Rule {
	return Rule{
		ID:       "LINT001",
		Severity: SeverityError,
		Check: func(bundle *PolicyBundle) []Finding {
			if bundle.Version == "" {
				return []Finding{{
					RuleID:     "LINT001",
					Severity:   SeverityError,
					Message:    "policy bundle version is required",
					Path:       "$.version",
					Suggestion: "set version to a semantic version string (e.g. \"1.0.0\")",
				}}
			}
			return nil
		},
	}
}

// ruleRequireID returns a Rule that errors when the bundle ID is empty.
func ruleRequireID() Rule {
	return Rule{
		ID:       "LINT002",
		Severity: SeverityError,
		Check: func(bundle *PolicyBundle) []Finding {
			if bundle.ID == "" {
				return []Finding{{
					RuleID:     "LINT002",
					Severity:   SeverityError,
					Message:    "policy bundle ID is required",
					Path:       "$.id",
					Suggestion: "set id to a unique identifier for this bundle",
				}}
			}
			return nil
		},
	}
}

// ruleNonEmptyRules returns a Rule that errors when the bundle contains
// no policy rules.
func ruleNonEmptyRules() Rule {
	return Rule{
		ID:       "LINT003",
		Severity: SeverityError,
		Check: func(bundle *PolicyBundle) []Finding {
			if len(bundle.Rules) == 0 {
				return []Finding{{
					RuleID:     "LINT003",
					Severity:   SeverityError,
					Message:    "policy bundle must contain at least one rule",
					Path:       "$.rules",
					Suggestion: "add one or more rules to the bundle",
				}}
			}
			return nil
		},
	}
}

// ruleValidActions returns a Rule that errors when any policy rule uses
// an action outside {ALLOW, DENY, ESCALATE}.
func ruleValidActions() Rule {
	return Rule{
		ID:       "LINT004",
		Severity: SeverityError,
		Check: func(bundle *PolicyBundle) []Finding {
			var findings []Finding
			for i, r := range bundle.Rules {
				if !validActions[r.Action] {
					findings = append(findings, Finding{
						RuleID:     "LINT004",
						Severity:   SeverityError,
						Message:    fmt.Sprintf("rule %q has invalid action %q", r.Name, r.Action),
						Path:       fmt.Sprintf("$.rules[%d].action", i),
						Suggestion: "action must be one of: ALLOW, DENY, ESCALATE",
					})
				}
			}
			return findings
		},
	}
}

// ruleNoDuplicateNames returns a Rule that warns when two or more policy
// rules share the same name.
func ruleNoDuplicateNames() Rule {
	return Rule{
		ID:       "LINT005",
		Severity: SeverityWarning,
		Check: func(bundle *PolicyBundle) []Finding {
			seen := make(map[string]int) // name → first index
			var findings []Finding
			for i, r := range bundle.Rules {
				if first, ok := seen[r.Name]; ok {
					findings = append(findings, Finding{
						RuleID:     "LINT005",
						Severity:   SeverityWarning,
						Message:    fmt.Sprintf("duplicate rule name %q (first at index %d)", r.Name, first),
						Path:       fmt.Sprintf("$.rules[%d].name", i),
						Suggestion: "give each rule a unique name for clarity",
					})
				} else {
					seen[r.Name] = i
				}
			}
			return findings
		},
	}
}

// ruleNoOverlappingPriorities returns a Rule that warns when two or more
// policy rules share the same priority value.
func ruleNoOverlappingPriorities() Rule {
	return Rule{
		ID:       "LINT006",
		Severity: SeverityWarning,
		Check: func(bundle *PolicyBundle) []Finding {
			seen := make(map[int]int) // priority → first index
			var findings []Finding
			for i, r := range bundle.Rules {
				if first, ok := seen[r.Priority]; ok {
					findings = append(findings, Finding{
						RuleID:     "LINT006",
						Severity:   SeverityWarning,
						Message:    fmt.Sprintf("rule %q shares priority %d with rule at index %d", r.Name, r.Priority, first),
						Path:       fmt.Sprintf("$.rules[%d].priority", i),
						Suggestion: "assign distinct priorities to control evaluation order",
					})
				} else {
					seen[r.Priority] = i
				}
			}
			return findings
		},
	}
}

// ruleDenyDefault returns a Rule that warns when no DENY rule exists,
// which may indicate a fail-open policy.
func ruleDenyDefault() Rule {
	return Rule{
		ID:       "LINT007",
		Severity: SeverityWarning,
		Check: func(bundle *PolicyBundle) []Finding {
			for _, r := range bundle.Rules {
				if r.Action == "DENY" {
					return nil
				}
			}
			return []Finding{{
				RuleID:     "LINT007",
				Severity:   SeverityWarning,
				Message:    "no DENY rule found; policy may be fail-open",
				Path:       "$.rules",
				Suggestion: "add a default DENY rule to enforce fail-closed behaviour",
			}}
		},
	}
}

// ruleContentHashPresent returns a Rule that notes when the content_hash
// field is absent, indicating an unsigned bundle.
func ruleContentHashPresent() Rule {
	return Rule{
		ID:       "LINT008",
		Severity: SeverityInfo,
		Check: func(bundle *PolicyBundle) []Finding {
			if bundle.ContentHash == "" {
				return []Finding{{
					RuleID:     "LINT008",
					Severity:   SeverityInfo,
					Message:    "content_hash is missing; bundle is unsigned",
					Path:       "$.content_hash",
					Suggestion: "sign the bundle to enable integrity verification",
				}}
			}
			return nil
		},
	}
}

// maxRuleCount is the threshold above which a performance warning fires.
const maxRuleCount = 1000

// ruleMaxRuleCount returns a Rule that warns when a bundle contains more
// than maxRuleCount rules, which may degrade evaluation performance.
func ruleMaxRuleCount() Rule {
	return Rule{
		ID:       "LINT009",
		Severity: SeverityWarning,
		Check: func(bundle *PolicyBundle) []Finding {
			if len(bundle.Rules) > maxRuleCount {
				return []Finding{{
					RuleID:     "LINT009",
					Severity:   SeverityWarning,
					Message:    fmt.Sprintf("bundle contains %d rules (exceeds %d); may impact performance", len(bundle.Rules), maxRuleCount),
					Path:       "$.rules",
					Suggestion: "split large bundles into composable sub-bundles",
				}}
			}
			return nil
		},
	}
}

// ruleConditionsNotEmpty returns a Rule that warns when a policy rule has
// no conditions, meaning it matches every request unconditionally.
func ruleConditionsNotEmpty() Rule {
	return Rule{
		ID:       "LINT010",
		Severity: SeverityWarning,
		Check: func(bundle *PolicyBundle) []Finding {
			var findings []Finding
			for i, r := range bundle.Rules {
				if len(r.Conditions) == 0 {
					findings = append(findings, Finding{
						RuleID:     "LINT010",
						Severity:   SeverityWarning,
						Message:    fmt.Sprintf("rule %q has no conditions; it matches all requests", r.Name),
						Path:       fmt.Sprintf("$.rules[%d].conditions", i),
						Suggestion: "add conditions to narrow the rule's scope",
					})
				}
			}
			return findings
		},
	}
}
