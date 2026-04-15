// Package suggest generates policy recommendations from ProofGraph analysis.
// Per arXiv 2601.10440, policies can be learned from control flow dependencies.
// By analyzing historical decisions, HELM suggests new policy rules that would
// have caught previously-denied or escalated requests earlier.
//
// Design invariants:
//   - Suggestions are advisory (never auto-applied)
//   - Based on statistical patterns in ProofGraph data
//   - Deterministic given same input history
//   - Thread-safe
package suggest

import (
	"crypto/sha256"
	"fmt"
	"sort"
)

// PolicySuggestion describes a single policy rule recommendation derived
// from statistical analysis of historical decision events.
type PolicySuggestion struct {
	RuleID      string  `json:"rule_id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Condition   string  `json:"condition"`  // CEL expression
	Action      string  `json:"action"`     // DENY, ALLOW, ESCALATE
	Confidence  float64 `json:"confidence"` // 0.0-1.0
	BasedOn     int     `json:"based_on"`   // Number of historical events
	Category    string  `json:"category"`   // DENY_PATTERN, ALLOW_SHORTCUT, ESCALATION_REDUCE
}

// DecisionEvent represents a single historical governance decision.
type DecisionEvent struct {
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Principal string `json:"principal"`
	Verdict   string `json:"verdict"`
	Timestamp int64  `json:"timestamp"`
}

// SuggestionOption configures a SuggestionEngine.
type SuggestionOption func(*SuggestionEngine)

// SuggestionEngine analyzes historical decision events and produces
// policy suggestions. It is safe for concurrent use; Analyze is a
// pure function over its input slice.
type SuggestionEngine struct {
	minSampleSize int
}

// Default thresholds for pattern detection.
const (
	defaultMinSampleSize = 10

	// denyThreshold is the minimum fraction of DENY verdicts in a group
	// before a DENY rule is suggested.
	denyThreshold = 0.80

	// allowThreshold is the minimum fraction of ALLOW verdicts in a group
	// before an ALLOW shortcut is suggested.
	allowThreshold = 0.95

	// escalateThreshold is the minimum fraction of ESCALATE verdicts in a
	// group before a tighter-policy suggestion is emitted.
	escalateThreshold = 0.30
)

// NewSuggestionEngine creates a SuggestionEngine with the given options.
// Without options, the engine uses a minimum sample size of 10 events per
// (action, resource) group before emitting any suggestions.
func NewSuggestionEngine(opts ...SuggestionOption) *SuggestionEngine {
	e := &SuggestionEngine{
		minSampleSize: defaultMinSampleSize,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// WithMinSampleSize returns a SuggestionOption that sets the minimum
// number of events in a group before suggestions are produced.
func WithMinSampleSize(n int) SuggestionOption {
	return func(e *SuggestionEngine) {
		if n > 0 {
			e.minSampleSize = n
		}
	}
}

// groupKey identifies an (action, resource) pair for aggregation.
type groupKey struct {
	action   string
	resource string
}

// groupStats tracks verdict counts for a single (action, resource) group.
type groupStats struct {
	total    int
	deny     int
	allow    int
	escalate int
}

// Analyze examines the given events and returns policy suggestions
// sorted by confidence descending. Groups with fewer events than
// minSampleSize are skipped. The result is deterministic: given the
// same input slice, the same suggestions are always returned.
func (e *SuggestionEngine) Analyze(events []DecisionEvent) []PolicySuggestion {
	if len(events) == 0 {
		return nil
	}

	// Step 1: Group events by (action, resource).
	groups := make(map[groupKey]*groupStats)
	for _, ev := range events {
		k := groupKey{action: ev.Action, resource: ev.Resource}
		s, ok := groups[k]
		if !ok {
			s = &groupStats{}
			groups[k] = s
		}
		s.total++
		switch ev.Verdict {
		case "DENY":
			s.deny++
		case "ALLOW":
			s.allow++
		case "ESCALATE":
			s.escalate++
		}
	}

	// Step 2: Evaluate each group against thresholds.
	var suggestions []PolicySuggestion
	for k, s := range groups {
		if s.total < e.minSampleSize {
			continue
		}

		denyRate := float64(s.deny) / float64(s.total)
		allowRate := float64(s.allow) / float64(s.total)
		escalateRate := float64(s.escalate) / float64(s.total)

		if denyRate > denyThreshold {
			suggestions = append(suggestions, PolicySuggestion{
				RuleID:      ruleID(k, "DENY_PATTERN"),
				Name:        fmt.Sprintf("auto-deny-%s-%s", k.action, k.resource),
				Description: fmt.Sprintf("Action %q on resource %q was denied %.0f%% of the time (%d events). Consider adding a DENY rule.", k.action, k.resource, denyRate*100, s.total),
				Condition:   fmt.Sprintf(`request.action == "%s" && request.resource == "%s"`, k.action, k.resource),
				Action:      "DENY",
				Confidence:  denyRate,
				BasedOn:     s.total,
				Category:    "DENY_PATTERN",
			})
		}

		if allowRate > allowThreshold {
			suggestions = append(suggestions, PolicySuggestion{
				RuleID:      ruleID(k, "ALLOW_SHORTCUT"),
				Name:        fmt.Sprintf("auto-allow-%s-%s", k.action, k.resource),
				Description: fmt.Sprintf("Action %q on resource %q was allowed %.0f%% of the time (%d events). Consider adding an ALLOW shortcut to reduce evaluation overhead.", k.action, k.resource, allowRate*100, s.total),
				Condition:   fmt.Sprintf(`request.action == "%s" && request.resource == "%s"`, k.action, k.resource),
				Action:      "ALLOW",
				Confidence:  allowRate * 0.8, // Medium confidence for shortcuts
				BasedOn:     s.total,
				Category:    "ALLOW_SHORTCUT",
			})
		}

		if escalateRate > escalateThreshold {
			suggestions = append(suggestions, PolicySuggestion{
				RuleID:      ruleID(k, "ESCALATION_REDUCE"),
				Name:        fmt.Sprintf("reduce-escalation-%s-%s", k.action, k.resource),
				Description: fmt.Sprintf("Action %q on resource %q was escalated %.0f%% of the time (%d events). Consider adding a tighter policy to reduce human review burden.", k.action, k.resource, escalateRate*100, s.total),
				Condition:   fmt.Sprintf(`request.action == "%s" && request.resource == "%s"`, k.action, k.resource),
				Action:      "ESCALATE",
				Confidence:  escalateRate * 0.7, // Lower confidence for escalation patterns
				BasedOn:     s.total,
				Category:    "ESCALATION_REDUCE",
			})
		}
	}

	// Step 3: Sort by confidence descending, then by RuleID for determinism.
	sort.Slice(suggestions, func(i, j int) bool {
		if suggestions[i].Confidence != suggestions[j].Confidence {
			return suggestions[i].Confidence > suggestions[j].Confidence
		}
		return suggestions[i].RuleID < suggestions[j].RuleID
	})

	return suggestions
}

// ruleID produces a deterministic identifier for a suggestion based on
// the group key and category. The ID is a truncated SHA-256 hash to
// ensure consistent naming across runs.
func ruleID(k groupKey, category string) string {
	h := sha256.Sum256([]byte(k.action + ":" + k.resource + ":" + category))
	return fmt.Sprintf("SUG-%x", h[:6])
}
