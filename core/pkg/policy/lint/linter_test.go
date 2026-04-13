package lint

import (
	"encoding/json"
	"strings"
	"testing"
)

// validBundle returns a minimal PolicyBundle that passes all built-in rules.
func validBundle() *PolicyBundle {
	return &PolicyBundle{
		Version:     "1.0.0",
		ID:          "test-bundle",
		ContentHash: "sha256:abc123",
		Rules: []PolicyRule{
			{
				Name:       "deny-all",
				Action:     "DENY",
				Priority:   100,
				Conditions: map[string]any{"scope": "all"},
			},
			{
				Name:       "allow-read",
				Action:     "ALLOW",
				Priority:   10,
				Conditions: map[string]any{"action": "read"},
			},
		},
	}
}

// validBundleJSON returns the JSON representation of validBundle.
func validBundleJSON() []byte {
	data, err := json.Marshal(validBundle())
	if err != nil {
		panic("failed to marshal valid bundle: " + err.Error())
	}
	return data
}

// findByRule returns findings matching the given rule ID.
func findByRule(result *LintResult, ruleID string) []Finding {
	var matched []Finding
	for _, f := range result.Findings {
		if f.RuleID == ruleID {
			matched = append(matched, f)
		}
	}
	return matched
}

// TestValidBundlePassesAllChecks verifies that a well-formed bundle
// produces no ERROR findings and reports as valid.
func TestValidBundlePassesAllChecks(t *testing.T) {
	l := New()
	result := l.Lint(validBundle())

	if !result.Valid {
		t.Errorf("expected valid bundle, got Valid=false with findings: %+v", result.Findings)
	}
	if result.ErrorCount != 0 {
		t.Errorf("expected 0 errors, got %d", result.ErrorCount)
	}
}

// TestMissingVersionTriggersError verifies LINT001.
func TestMissingVersionTriggersError(t *testing.T) {
	b := validBundle()
	b.Version = ""

	l := New()
	result := l.Lint(b)

	findings := findByRule(result, "LINT001")
	if len(findings) == 0 {
		t.Fatal("expected LINT001 finding for missing version")
	}
	if findings[0].Severity != SeverityError {
		t.Errorf("expected ERROR severity, got %s", findings[0].Severity)
	}
	if !result.Valid {
		// Expected: should not be valid because we have an error.
	} else {
		t.Error("expected Valid=false when version is missing")
	}
}

// TestMissingIDTriggersError verifies LINT002.
func TestMissingIDTriggersError(t *testing.T) {
	b := validBundle()
	b.ID = ""

	l := New()
	result := l.Lint(b)

	findings := findByRule(result, "LINT002")
	if len(findings) == 0 {
		t.Fatal("expected LINT002 finding for missing ID")
	}
	if findings[0].Severity != SeverityError {
		t.Errorf("expected ERROR severity, got %s", findings[0].Severity)
	}
	if result.Valid {
		t.Error("expected Valid=false when ID is missing")
	}
}

// TestEmptyRulesTriggersError verifies LINT003.
func TestEmptyRulesTriggersError(t *testing.T) {
	b := validBundle()
	b.Rules = nil

	l := New()
	result := l.Lint(b)

	findings := findByRule(result, "LINT003")
	if len(findings) == 0 {
		t.Fatal("expected LINT003 finding for empty rules")
	}
	if findings[0].Severity != SeverityError {
		t.Errorf("expected ERROR severity, got %s", findings[0].Severity)
	}
	if result.Valid {
		t.Error("expected Valid=false when rules are empty")
	}
}

// TestInvalidActionTriggersError verifies LINT004.
func TestInvalidActionTriggersError(t *testing.T) {
	b := validBundle()
	b.Rules = append(b.Rules, PolicyRule{
		Name:       "bad-action",
		Action:     "PERMIT",
		Priority:   200,
		Conditions: map[string]any{"x": 1},
	})

	l := New()
	result := l.Lint(b)

	findings := findByRule(result, "LINT004")
	if len(findings) == 0 {
		t.Fatal("expected LINT004 finding for invalid action")
	}
	if findings[0].Severity != SeverityError {
		t.Errorf("expected ERROR severity, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Message, "PERMIT") {
		t.Errorf("expected message to mention the invalid action, got %q", findings[0].Message)
	}
}

// TestDuplicateNamesTriggersWarning verifies LINT005.
func TestDuplicateNamesTriggersWarning(t *testing.T) {
	b := validBundle()
	b.Rules = []PolicyRule{
		{Name: "same-name", Action: "DENY", Priority: 1, Conditions: map[string]any{"a": 1}},
		{Name: "same-name", Action: "ALLOW", Priority: 2, Conditions: map[string]any{"b": 2}},
	}

	l := New()
	result := l.Lint(b)

	findings := findByRule(result, "LINT005")
	if len(findings) == 0 {
		t.Fatal("expected LINT005 finding for duplicate names")
	}
	if findings[0].Severity != SeverityWarning {
		t.Errorf("expected WARNING severity, got %s", findings[0].Severity)
	}
}

// TestOverlappingPrioritiesTriggersWarning verifies LINT006.
func TestOverlappingPrioritiesTriggersWarning(t *testing.T) {
	b := validBundle()
	b.Rules = []PolicyRule{
		{Name: "rule-a", Action: "DENY", Priority: 50, Conditions: map[string]any{"a": 1}},
		{Name: "rule-b", Action: "ALLOW", Priority: 50, Conditions: map[string]any{"b": 2}},
	}

	l := New()
	result := l.Lint(b)

	findings := findByRule(result, "LINT006")
	if len(findings) == 0 {
		t.Fatal("expected LINT006 finding for overlapping priorities")
	}
	if findings[0].Severity != SeverityWarning {
		t.Errorf("expected WARNING severity, got %s", findings[0].Severity)
	}
}

// TestNoDenyRuleTriggersWarning verifies LINT007.
func TestNoDenyRuleTriggersWarning(t *testing.T) {
	b := validBundle()
	b.Rules = []PolicyRule{
		{Name: "allow-only", Action: "ALLOW", Priority: 1, Conditions: map[string]any{"a": 1}},
	}

	l := New()
	result := l.Lint(b)

	findings := findByRule(result, "LINT007")
	if len(findings) == 0 {
		t.Fatal("expected LINT007 finding for missing DENY rule")
	}
	if findings[0].Severity != SeverityWarning {
		t.Errorf("expected WARNING severity, got %s", findings[0].Severity)
	}
}

// TestMissingContentHashTriggersInfo verifies LINT008.
func TestMissingContentHashTriggersInfo(t *testing.T) {
	b := validBundle()
	b.ContentHash = ""

	l := New()
	result := l.Lint(b)

	findings := findByRule(result, "LINT008")
	if len(findings) == 0 {
		t.Fatal("expected LINT008 finding for missing content_hash")
	}
	if findings[0].Severity != SeverityInfo {
		t.Errorf("expected INFO severity, got %s", findings[0].Severity)
	}
	// INFO findings should not invalidate the bundle.
	if !result.Valid {
		t.Error("expected Valid=true; INFO finding should not block deployment")
	}
}

// TestLargeRuleCountTriggersWarning verifies LINT009.
func TestLargeRuleCountTriggersWarning(t *testing.T) {
	b := validBundle()
	b.Rules = make([]PolicyRule, maxRuleCount+1)
	for i := range b.Rules {
		b.Rules[i] = PolicyRule{
			Name:       "rule-" + strings.Repeat("x", 5),
			Action:     "DENY",
			Priority:   i,
			Conditions: map[string]any{"i": i},
		}
	}

	l := New()
	result := l.Lint(b)

	findings := findByRule(result, "LINT009")
	if len(findings) == 0 {
		t.Fatal("expected LINT009 finding for large rule count")
	}
	if findings[0].Severity != SeverityWarning {
		t.Errorf("expected WARNING severity, got %s", findings[0].Severity)
	}
}

// TestUnconditionalRuleTriggersWarning verifies LINT010.
func TestUnconditionalRuleTriggersWarning(t *testing.T) {
	b := validBundle()
	b.Rules = []PolicyRule{
		{Name: "unconditional", Action: "DENY", Priority: 1},
	}

	l := New()
	result := l.Lint(b)

	findings := findByRule(result, "LINT010")
	if len(findings) == 0 {
		t.Fatal("expected LINT010 finding for unconditional rule")
	}
	if findings[0].Severity != SeverityWarning {
		t.Errorf("expected WARNING severity, got %s", findings[0].Severity)
	}
}

// TestLintJSONValid verifies that well-formed JSON is parsed and linted.
func TestLintJSONValid(t *testing.T) {
	l := New()
	result, err := l.LintJSON(validBundleJSON())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid result, got findings: %+v", result.Findings)
	}
	if result.ErrorCount != 0 {
		t.Errorf("expected 0 errors, got %d", result.ErrorCount)
	}
}

// TestLintJSONInvalid verifies that malformed JSON returns an error.
func TestLintJSONInvalid(t *testing.T) {
	l := New()
	_, err := l.LintJSON([]byte("{not valid json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "lint: failed to parse policy bundle JSON") {
		t.Errorf("expected wrapped error message, got: %v", err)
	}
}

// TestCustomRuleIntegration verifies that a user-supplied rule is
// evaluated alongside built-in rules.
func TestCustomRuleIntegration(t *testing.T) {
	customRule := Rule{
		ID:       "CUSTOM001",
		Severity: SeverityError,
		Check: func(bundle *PolicyBundle) []Finding {
			if bundle.Metadata == nil || bundle.Metadata["owner"] == nil {
				return []Finding{{
					RuleID:   "CUSTOM001",
					Severity: SeverityError,
					Message:  "metadata.owner is required by organisation policy",
					Path:     "$.metadata.owner",
				}}
			}
			return nil
		},
	}

	l := New(WithRule(customRule))
	b := validBundle()
	result := l.Lint(b)

	findings := findByRule(result, "CUSTOM001")
	if len(findings) == 0 {
		t.Fatal("expected CUSTOM001 finding from custom rule")
	}
	if result.Valid {
		t.Error("expected Valid=false when custom ERROR rule fires")
	}
}

// TestMultipleFindingsAccumulated verifies that a bundle with many
// problems accumulates all findings from all rules.
func TestMultipleFindingsAccumulated(t *testing.T) {
	b := &PolicyBundle{
		// Missing version → LINT001
		// Missing ID → LINT002
		// No rules → LINT003
		// No content hash → LINT008
	}

	l := New()
	result := l.Lint(b)

	if len(result.Findings) < 4 {
		t.Errorf("expected at least 4 findings, got %d: %+v", len(result.Findings), result.Findings)
	}

	expectedRules := map[string]bool{
		"LINT001": false,
		"LINT002": false,
		"LINT003": false,
		"LINT008": false,
	}
	for _, f := range result.Findings {
		if _, ok := expectedRules[f.RuleID]; ok {
			expectedRules[f.RuleID] = true
		}
	}
	for id, found := range expectedRules {
		if !found {
			t.Errorf("expected finding for rule %s but it was absent", id)
		}
	}
}

// TestCountAccuracy verifies that ErrorCount, WarnCount, and InfoCount
// reflect the actual severity distribution of findings.
func TestCountAccuracy(t *testing.T) {
	b := &PolicyBundle{
		Version: "1.0.0",
		ID:      "counts-test",
		// ContentHash empty → 1 INFO (LINT008)
		Rules: []PolicyRule{
			// No conditions → 1 WARNING (LINT010)
			// Only ALLOW, no DENY → 1 WARNING (LINT007)
			{Name: "allow-all", Action: "ALLOW", Priority: 1},
			// Invalid action → 1 ERROR (LINT004)
			{Name: "bad", Action: "NOPE", Priority: 2, Conditions: map[string]any{"a": 1}},
		},
	}

	l := New()
	result := l.Lint(b)

	if result.ErrorCount < 1 {
		t.Errorf("expected at least 1 error, got %d", result.ErrorCount)
	}
	if result.WarnCount < 1 {
		t.Errorf("expected at least 1 warning, got %d", result.WarnCount)
	}
	if result.InfoCount < 1 {
		t.Errorf("expected at least 1 info, got %d", result.InfoCount)
	}

	// Verify the counts sum to total findings.
	total := result.ErrorCount + result.WarnCount + result.InfoCount
	if total != len(result.Findings) {
		t.Errorf("counts sum (%d) does not match total findings (%d)", total, len(result.Findings))
	}
}

// TestValidFlagTrueWhenNoErrors verifies the Valid flag is true when
// only WARNING and INFO findings exist (no ERRORs).
func TestValidFlagTrueWhenNoErrors(t *testing.T) {
	b := &PolicyBundle{
		Version:     "1.0.0",
		ID:          "valid-flag-test",
		ContentHash: "", // INFO
		Rules: []PolicyRule{
			// No conditions → WARNING (LINT010)
			// Only ALLOW → WARNING (LINT007)
			{Name: "allow-all", Action: "ALLOW", Priority: 1},
		},
	}

	l := New()
	result := l.Lint(b)

	if result.ErrorCount != 0 {
		t.Errorf("expected 0 errors, got %d; findings: %+v", result.ErrorCount, result.Findings)
	}
	if !result.Valid {
		t.Error("expected Valid=true when only WARNINGs and INFOs exist")
	}
	if result.WarnCount == 0 {
		t.Error("expected at least one warning")
	}
	if result.InfoCount == 0 {
		t.Error("expected at least one info finding")
	}
}

// TestValidFlagFalseWhenErrors verifies the Valid flag is false as soon
// as any ERROR-severity finding is present.
func TestValidFlagFalseWhenErrors(t *testing.T) {
	b := &PolicyBundle{
		// Missing version → ERROR
		ID:          "error-test",
		ContentHash: "sha256:ok",
		Rules: []PolicyRule{
			{Name: "deny", Action: "DENY", Priority: 1, Conditions: map[string]any{"a": 1}},
		},
	}

	l := New()
	result := l.Lint(b)

	if result.Valid {
		t.Error("expected Valid=false when ERROR finding exists")
	}
	if result.ErrorCount == 0 {
		t.Error("expected at least 1 error")
	}
}

// TestLintJSONPreservesRawJSON verifies that RawJSON is populated after
// parsing, allowing structural checks to access the original input.
func TestLintJSONPreservesRawJSON(t *testing.T) {
	data := validBundleJSON()

	l := New()
	// Use a custom rule to inspect RawJSON.
	inspected := false
	l.rules = append(l.rules, Rule{
		ID:       "INSPECT_RAW",
		Severity: SeverityInfo,
		Check: func(bundle *PolicyBundle) []Finding {
			if len(bundle.RawJSON) > 0 {
				inspected = true
			}
			return nil
		},
	})

	_, err := l.LintJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !inspected {
		t.Error("expected RawJSON to be populated after LintJSON")
	}
}

// TestFindingJSONSerialization verifies that findings serialize correctly
// and omit empty optional fields.
func TestFindingJSONSerialization(t *testing.T) {
	f := Finding{
		RuleID:   "LINT001",
		Severity: SeverityError,
		Message:  "version required",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("failed to marshal finding: %v", err)
	}

	s := string(data)
	if strings.Contains(s, "path") {
		t.Error("expected path to be omitted when empty")
	}
	if strings.Contains(s, "suggestion") {
		t.Error("expected suggestion to be omitted when empty")
	}
	if !strings.Contains(s, `"rule_id":"LINT001"`) {
		t.Errorf("expected rule_id in JSON, got: %s", s)
	}
}

// TestAllValidActions verifies that ALLOW, DENY, and ESCALATE are all accepted.
func TestAllValidActions(t *testing.T) {
	for _, action := range []string{"ALLOW", "DENY", "ESCALATE"} {
		b := &PolicyBundle{
			Version:     "1.0.0",
			ID:          "action-test",
			ContentHash: "sha256:ok",
			Rules: []PolicyRule{
				{Name: "rule-" + action, Action: action, Priority: 1, Conditions: map[string]any{"a": 1}},
			},
		}
		// Add a DENY if testing non-DENY actions to avoid LINT007.
		if action != "DENY" {
			b.Rules = append(b.Rules, PolicyRule{
				Name: "deny-default", Action: "DENY", Priority: 99, Conditions: map[string]any{"b": 2},
			})
		}

		l := New()
		result := l.Lint(b)

		findings := findByRule(result, "LINT004")
		if len(findings) > 0 {
			t.Errorf("action %q should be valid but got LINT004: %+v", action, findings)
		}
	}
}

// TestMultipleCustomRules verifies that several custom rules work together.
func TestMultipleCustomRules(t *testing.T) {
	rule1 := Rule{
		ID:       "CUSTOM_A",
		Severity: SeverityWarning,
		Check: func(bundle *PolicyBundle) []Finding {
			return []Finding{{RuleID: "CUSTOM_A", Severity: SeverityWarning, Message: "custom A fired"}}
		},
	}
	rule2 := Rule{
		ID:       "CUSTOM_B",
		Severity: SeverityInfo,
		Check: func(bundle *PolicyBundle) []Finding {
			return []Finding{{RuleID: "CUSTOM_B", Severity: SeverityInfo, Message: "custom B fired"}}
		},
	}

	l := New(WithRule(rule1), WithRule(rule2))
	result := l.Lint(validBundle())

	if len(findByRule(result, "CUSTOM_A")) == 0 {
		t.Error("expected CUSTOM_A finding")
	}
	if len(findByRule(result, "CUSTOM_B")) == 0 {
		t.Error("expected CUSTOM_B finding")
	}
}

// TestLintResultJSONSerialization verifies round-trip JSON encoding of
// LintResult.
func TestLintResultJSONSerialization(t *testing.T) {
	l := New()
	result := l.Lint(validBundle())

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal LintResult: %v", err)
	}

	var decoded LintResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal LintResult: %v", err)
	}

	if decoded.Valid != result.Valid {
		t.Errorf("Valid mismatch: %v vs %v", decoded.Valid, result.Valid)
	}
	if decoded.ErrorCount != result.ErrorCount {
		t.Errorf("ErrorCount mismatch: %d vs %d", decoded.ErrorCount, result.ErrorCount)
	}
}

// TestEmptyLinter verifies that a linter with no rules produces a clean
// result.
func TestEmptyLinter(t *testing.T) {
	l := &Linter{} // No built-in rules.
	result := l.Lint(validBundle())

	if !result.Valid {
		t.Error("expected valid result from empty linter")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

// TestDuplicateNamesMultipleOccurrences verifies that three rules with
// the same name produce two findings (second and third occurrence).
func TestDuplicateNamesMultipleOccurrences(t *testing.T) {
	b := validBundle()
	b.Rules = []PolicyRule{
		{Name: "dup", Action: "DENY", Priority: 1, Conditions: map[string]any{"a": 1}},
		{Name: "dup", Action: "ALLOW", Priority: 2, Conditions: map[string]any{"b": 2}},
		{Name: "dup", Action: "ESCALATE", Priority: 3, Conditions: map[string]any{"c": 3}},
	}

	l := New()
	result := l.Lint(b)

	findings := findByRule(result, "LINT005")
	if len(findings) != 2 {
		t.Errorf("expected 2 LINT005 findings for 3 duplicate names, got %d", len(findings))
	}
}
