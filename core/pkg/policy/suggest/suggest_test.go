package suggest

import (
	"testing"
)

// makeEvents generates n DecisionEvents with the given action, resource,
// and verdict.
func makeEvents(action, resource, verdict string, n int) []DecisionEvent {
	events := make([]DecisionEvent, n)
	for i := range events {
		events[i] = DecisionEvent{
			Action:    action,
			Resource:  resource,
			Principal: "agent-1",
			Verdict:   verdict,
			Timestamp: int64(1000 + i),
		}
	}
	return events
}

// TestNoEvents verifies that an empty input produces no suggestions.
func TestNoEvents(t *testing.T) {
	e := NewSuggestionEngine()
	suggestions := e.Analyze(nil)
	if len(suggestions) != 0 {
		t.Errorf("expected 0 suggestions for nil events, got %d", len(suggestions))
	}

	suggestions = e.Analyze([]DecisionEvent{})
	if len(suggestions) != 0 {
		t.Errorf("expected 0 suggestions for empty events, got %d", len(suggestions))
	}
}

// TestBelowMinSampleSize verifies that groups below the minimum sample
// size produce no suggestions.
func TestBelowMinSampleSize(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(20))
	events := makeEvents("write", "db", "DENY", 15)

	suggestions := e.Analyze(events)
	if len(suggestions) != 0 {
		t.Errorf("expected 0 suggestions below min sample size, got %d", len(suggestions))
	}
}

// TestAllDenySuggestsDenyRule verifies that a group with >80% DENY
// verdicts produces a DENY_PATTERN suggestion.
func TestAllDenySuggestsDenyRule(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(5))
	events := makeEvents("exec", "shell", "DENY", 10)

	suggestions := e.Analyze(events)
	if len(suggestions) == 0 {
		t.Fatal("expected at least 1 suggestion for all-DENY group")
	}

	found := false
	for _, s := range suggestions {
		if s.Category == "DENY_PATTERN" && s.Action == "DENY" {
			found = true
			if s.Confidence != 1.0 {
				t.Errorf("expected confidence 1.0 for 100%% DENY, got %f", s.Confidence)
			}
			if s.BasedOn != 10 {
				t.Errorf("expected BasedOn=10, got %d", s.BasedOn)
			}
		}
	}
	if !found {
		t.Error("expected a DENY_PATTERN suggestion")
	}
}

// TestAllAllowSuggestsShortcut verifies that a group with >95% ALLOW
// verdicts produces an ALLOW_SHORTCUT suggestion.
func TestAllAllowSuggestsShortcut(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(5))
	events := makeEvents("read", "docs", "ALLOW", 20)

	suggestions := e.Analyze(events)
	if len(suggestions) == 0 {
		t.Fatal("expected at least 1 suggestion for all-ALLOW group")
	}

	found := false
	for _, s := range suggestions {
		if s.Category == "ALLOW_SHORTCUT" && s.Action == "ALLOW" {
			found = true
			// 100% allow rate * 0.8 = 0.8 confidence
			if s.Confidence != 0.8 {
				t.Errorf("expected confidence 0.8 for 100%% ALLOW shortcut, got %f", s.Confidence)
			}
			if s.BasedOn != 20 {
				t.Errorf("expected BasedOn=20, got %d", s.BasedOn)
			}
		}
	}
	if !found {
		t.Error("expected an ALLOW_SHORTCUT suggestion")
	}
}

// TestMixedEscalationSuggestsReduction verifies that a group with >30%
// ESCALATE verdicts produces an ESCALATION_REDUCE suggestion.
func TestMixedEscalationSuggestsReduction(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(5))

	// 4 ESCALATE + 6 ALLOW = 40% escalation rate
	events := makeEvents("deploy", "prod", "ESCALATE", 4)
	events = append(events, makeEvents("deploy", "prod", "ALLOW", 6)...)

	suggestions := e.Analyze(events)
	if len(suggestions) == 0 {
		t.Fatal("expected at least 1 suggestion for mixed escalation group")
	}

	found := false
	for _, s := range suggestions {
		if s.Category == "ESCALATION_REDUCE" {
			found = true
			expectedConfidence := 0.4 * 0.7 // 40% escalation * 0.7
			if s.Confidence < expectedConfidence-0.001 || s.Confidence > expectedConfidence+0.001 {
				t.Errorf("expected confidence ~%.3f, got %f", expectedConfidence, s.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected an ESCALATION_REDUCE suggestion")
	}
}

// TestConfidenceSortOrder verifies that suggestions are sorted by
// confidence descending.
func TestConfidenceSortOrder(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(5))

	// Group 1: 100% DENY → confidence 1.0
	events := makeEvents("exec", "shell", "DENY", 10)
	// Group 2: 100% ALLOW → confidence 0.8 (shortcut)
	events = append(events, makeEvents("read", "docs", "ALLOW", 10)...)
	// Group 3: 40% ESCALATE → confidence 0.28
	events = append(events, makeEvents("deploy", "prod", "ESCALATE", 4)...)
	events = append(events, makeEvents("deploy", "prod", "ALLOW", 6)...)

	suggestions := e.Analyze(events)
	if len(suggestions) < 2 {
		t.Fatalf("expected at least 2 suggestions, got %d", len(suggestions))
	}

	for i := 1; i < len(suggestions); i++ {
		if suggestions[i].Confidence > suggestions[i-1].Confidence {
			t.Errorf("suggestions not sorted by confidence: index %d (%.3f) > index %d (%.3f)",
				i, suggestions[i].Confidence, i-1, suggestions[i-1].Confidence)
		}
	}
}

// TestMultipleGroups verifies that distinct (action, resource) pairs are
// analyzed independently.
func TestMultipleGroups(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(5))

	// Group A: all DENY
	events := makeEvents("write", "secrets", "DENY", 10)
	// Group B: all ALLOW
	events = append(events, makeEvents("read", "public", "ALLOW", 10)...)

	suggestions := e.Analyze(events)

	categories := make(map[string]bool)
	for _, s := range suggestions {
		categories[s.Category] = true
	}

	if !categories["DENY_PATTERN"] {
		t.Error("expected a DENY_PATTERN suggestion for the write/secrets group")
	}
	if !categories["ALLOW_SHORTCUT"] {
		t.Error("expected an ALLOW_SHORTCUT suggestion for the read/public group")
	}
}

// TestConfidenceCalculationDeny verifies confidence for a group that is
// exactly at the DENY threshold boundary.
func TestConfidenceCalculationDeny(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(5))

	// 81% DENY (just above 80% threshold): 81 DENY + 19 ALLOW = 100 events
	events := makeEvents("patch", "config", "DENY", 81)
	events = append(events, makeEvents("patch", "config", "ALLOW", 19)...)

	suggestions := e.Analyze(events)

	found := false
	for _, s := range suggestions {
		if s.Category == "DENY_PATTERN" {
			found = true
			expected := 0.81
			if s.Confidence < expected-0.001 || s.Confidence > expected+0.001 {
				t.Errorf("expected confidence ~%.2f, got %f", expected, s.Confidence)
			}
			if s.BasedOn != 100 {
				t.Errorf("expected BasedOn=100, got %d", s.BasedOn)
			}
		}
	}
	if !found {
		t.Error("expected a DENY_PATTERN suggestion at 81% deny rate")
	}
}

// TestBelowDenyThresholdNoSuggestion verifies that a group with exactly
// 80% DENY does not trigger a suggestion (threshold is >80%, not >=80%).
func TestBelowDenyThresholdNoSuggestion(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(5))

	// Exactly 80% DENY: 8 DENY + 2 ALLOW = 10 events
	events := makeEvents("patch", "config", "DENY", 8)
	events = append(events, makeEvents("patch", "config", "ALLOW", 2)...)

	suggestions := e.Analyze(events)

	for _, s := range suggestions {
		if s.Category == "DENY_PATTERN" {
			t.Error("did not expect a DENY_PATTERN suggestion at exactly 80% deny rate")
		}
	}
}

// TestDeterminism verifies that the same input always produces the
// same output.
func TestDeterminism(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(5))

	events := makeEvents("exec", "shell", "DENY", 10)
	events = append(events, makeEvents("read", "docs", "ALLOW", 10)...)

	first := e.Analyze(events)
	second := e.Analyze(events)

	if len(first) != len(second) {
		t.Fatalf("nondeterministic: first run produced %d suggestions, second produced %d",
			len(first), len(second))
	}

	for i := range first {
		if first[i].RuleID != second[i].RuleID {
			t.Errorf("nondeterministic: index %d RuleID %q vs %q",
				i, first[i].RuleID, second[i].RuleID)
		}
		if first[i].Confidence != second[i].Confidence {
			t.Errorf("nondeterministic: index %d Confidence %f vs %f",
				i, first[i].Confidence, second[i].Confidence)
		}
	}
}

// TestDefaultMinSampleSize verifies that the default engine uses a
// minimum sample size of 10.
func TestDefaultMinSampleSize(t *testing.T) {
	e := NewSuggestionEngine()

	// 9 events — below default threshold of 10.
	events := makeEvents("write", "db", "DENY", 9)
	suggestions := e.Analyze(events)
	if len(suggestions) != 0 {
		t.Errorf("expected 0 suggestions for 9 events with default min sample size, got %d", len(suggestions))
	}

	// 10 events — at default threshold.
	events = makeEvents("write", "db", "DENY", 10)
	suggestions = e.Analyze(events)
	if len(suggestions) == 0 {
		t.Error("expected suggestions for 10 events with default min sample size")
	}
}

// TestWithMinSampleSizeZero verifies that zero or negative values for
// min sample size are ignored (engine keeps its current value).
func TestWithMinSampleSizeZero(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(0))
	if e.minSampleSize != defaultMinSampleSize {
		t.Errorf("expected default min sample size %d, got %d", defaultMinSampleSize, e.minSampleSize)
	}

	e = NewSuggestionEngine(WithMinSampleSize(-5))
	if e.minSampleSize != defaultMinSampleSize {
		t.Errorf("expected default min sample size %d, got %d", defaultMinSampleSize, e.minSampleSize)
	}
}

// TestRuleIDDeterministic verifies that the same group key and category
// always produce the same rule ID.
func TestRuleIDDeterministic(t *testing.T) {
	k := groupKey{action: "exec", resource: "shell"}
	id1 := ruleID(k, "DENY_PATTERN")
	id2 := ruleID(k, "DENY_PATTERN")

	if id1 != id2 {
		t.Errorf("ruleID not deterministic: %q vs %q", id1, id2)
	}

	// Different category should produce different ID.
	id3 := ruleID(k, "ALLOW_SHORTCUT")
	if id1 == id3 {
		t.Errorf("expected different rule IDs for different categories, both got %q", id1)
	}
}

// TestSuggestionFields verifies that all fields of a suggestion are
// populated correctly.
func TestSuggestionFields(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(5))
	events := makeEvents("exec", "shell", "DENY", 10)

	suggestions := e.Analyze(events)
	if len(suggestions) == 0 {
		t.Fatal("expected at least 1 suggestion")
	}

	s := suggestions[0]
	if s.RuleID == "" {
		t.Error("expected non-empty RuleID")
	}
	if s.Name == "" {
		t.Error("expected non-empty Name")
	}
	if s.Description == "" {
		t.Error("expected non-empty Description")
	}
	if s.Condition == "" {
		t.Error("expected non-empty Condition (CEL expression)")
	}
	if s.Action == "" {
		t.Error("expected non-empty Action")
	}
	if s.BasedOn == 0 {
		t.Error("expected non-zero BasedOn")
	}
	if s.Category == "" {
		t.Error("expected non-empty Category")
	}
}

// TestNoSuggestionBelowAllThresholds verifies that a uniformly mixed
// group (no dominant verdict) produces no suggestions.
func TestNoSuggestionBelowAllThresholds(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(5))

	// 5 DENY + 5 ALLOW + 2 ESCALATE = 12 events
	// DENY: 42%, ALLOW: 42%, ESCALATE: 17% — all below thresholds
	events := makeEvents("update", "config", "DENY", 5)
	events = append(events, makeEvents("update", "config", "ALLOW", 5)...)
	events = append(events, makeEvents("update", "config", "ESCALATE", 2)...)

	suggestions := e.Analyze(events)
	if len(suggestions) != 0 {
		t.Errorf("expected 0 suggestions for uniformly mixed group, got %d: %+v",
			len(suggestions), suggestions)
	}
}

// TestCELConditionFormat verifies that the generated CEL expression
// references the correct action and resource.
func TestCELConditionFormat(t *testing.T) {
	e := NewSuggestionEngine(WithMinSampleSize(5))
	events := makeEvents("exec", "shell", "DENY", 10)

	suggestions := e.Analyze(events)
	if len(suggestions) == 0 {
		t.Fatal("expected at least 1 suggestion")
	}

	expected := `request.action == "exec" && request.resource == "shell"`
	if suggestions[0].Condition != expected {
		t.Errorf("expected CEL condition %q, got %q", expected, suggestions[0].Condition)
	}
}
