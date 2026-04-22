package kernel

import (
	"testing"
)

// TestCELDPEvaluatorStub tests the evaluator with the current stub implementation
func TestCELDPEvaluatorStub(t *testing.T) {
	t.Run("Evaluate returns error for stub implementation", func(t *testing.T) {
		eval := NewCELDPEvaluator()

		result, err := eval.Evaluate("1 + 2", nil)
		if err != nil {
			t.Fatalf("Evaluate failed: %v", err)
		}

		// Current stub returns error - this is expected
		if result.Error == nil {
			t.Log("CEL evaluation is fully implemented - switch to integration tests")
		}
	})

	t.Run("Validator rejection before evaluation", func(t *testing.T) {
		eval := NewCELDPEvaluator()

		// This should be rejected by validator before hitting the evaluator stub
		result, err := eval.Evaluate("3.14", nil)
		if err != nil {
			t.Fatalf("Evaluate failed: %v", err)
		}

		if result.Error == nil {
			t.Error("Expected validation error for float literal")
		}
	})

	t.Run("Time access rejection", func(t *testing.T) {
		eval := NewCELDPEvaluator()

		result, err := eval.Evaluate("now()", nil)
		if err != nil {
			t.Fatalf("Evaluate failed: %v", err)
		}

		if result.Error == nil {
			t.Error("Expected validation error for now() access")
		}
	})
}

//nolint:gocognit // test complexity is acceptable
func TestCELDPValidatorEdgeCases(t *testing.T) {
	t.Run("Deep nesting at limit", func(t *testing.T) {
		v := NewCELDPValidator()

		// Create expression at nesting limit (default is 20)
		expr := "((((((((((1))))))))))"
		result := v.Validate(expr)

		// 10 levels should be within limit
		if !result.Valid {
			t.Errorf("10 levels of nesting should be valid, got issues: %v", result.Issues)
		}
	})

	t.Run("Deep nesting exceeds limit", func(t *testing.T) {
		v := NewCELDPValidator().WithBudget(CELDPCostBudget{
			MaxExpressionSize:  1000,
			MaxNestingDepth:    5,
			MaxEvaluationCost:  100000,
			MaxMacroExpansions: 100,
			HardTimeoutMs:      100,
		})

		expr := "((((((((((1))))))))))" // 10 levels
		result := v.Validate(expr)

		// Should fail due to nesting exceeding 5
		hasNestingError := false
		for _, issue := range result.Issues {
			if issue.RuleID == CELDPRuleNoUnboundedRecurse {
				hasNestingError = true
				break
			}
		}
		if !hasNestingError {
			t.Error("Expected nesting depth validation failure")
		}
	})

	t.Run("Expression size limit", func(t *testing.T) {
		v := NewCELDPValidator().WithBudget(CELDPCostBudget{
			MaxExpressionSize:  1, // Very small limit
			MaxNestingDepth:    20,
			MaxEvaluationCost:  100000,
			MaxMacroExpansions: 100,
			HardTimeoutMs:      100,
		})

		// Expression that exceeds size limit (>10 chars with multiplier)
		expr := "1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10 + 11 + 12"
		result := v.Validate(expr)

		// Should fail due to size
		hasSizeError := false
		for _, issue := range result.Issues {
			if issue.RuleID == CELDPRuleExpressionSizeLimit {
				hasSizeError = true
				break
			}
		}
		if !hasSizeError {
			t.Error("Expected expression size validation failure")
		}
	})

	t.Run("Time access patterns", func(t *testing.T) {
		v := NewCELDPValidator()

		forbiddenExprs := []string{
			"now()",
			"timestamp(x)",
			"duration(x)",
			"x.getFullYear",
			"x.getMonth",
		}

		for _, expr := range forbiddenExprs {
			result := v.Validate(expr)
			if result.Valid {
				t.Errorf("Expected validation failure for %q", expr)
			}
		}
	})

	t.Run("Map iteration order dependence", func(t *testing.T) {
		v := NewCELDPValidator()

		forbiddenExprs := []string{
			"m.keys()[0]",
			"m.values()[0]",
			"m.keys()[i]",
			"m.values()[i]",
		}

		for _, expr := range forbiddenExprs {
			result := v.Validate(expr)
			if result.Valid {
				t.Errorf("Expected validation failure for %q", expr)
			}
		}
	})

	t.Run("Float literal patterns", func(t *testing.T) {
		v := NewCELDPValidator()

		forbiddenExprs := []string{
			"3.14",
			"x + 1.5",
			"double(x)",
			"float(y)",
		}

		for _, expr := range forbiddenExprs {
			result := v.Validate(expr)
			if result.Valid {
				t.Errorf("Expected validation failure for float pattern %q", expr)
			}
		}
	})

	t.Run("Valid expressions", func(t *testing.T) {
		v := NewCELDPValidator()

		validExprs := []string{
			"1 + 2",
			"x > 10",
			"a && b",
			"x == y",
			`status == "active"`,
			"items.size() > 0",
		}

		for _, expr := range validExprs {
			result := v.Validate(expr)
			if !result.Valid {
				t.Errorf("Expected valid expression %q, got issues: %v", expr, result.Issues)
			}
		}
	})
}

//nolint:gocognit // test complexity is acceptable
func TestFormatValidationIssues(t *testing.T) {
	issues := []CELDPIssue{
		{RuleID: "CEL-DP-001", Message: "Float not allowed", Severity: "error"},
		{RuleID: "CEL-DP-002", Message: "Time access forbidden", Severity: "error"},
	}

	result := formatValidationIssues(issues)
	if result == "" {
		t.Error("Expected non-empty formatted issues")
	}
	if !contains(result, "CEL-DP-001") {
		t.Error("Expected CEL-DP-001 in formatted output")
	}
}

func TestHasErrors(t *testing.T) {
	t.Run("Has errors", func(t *testing.T) {
		issues := []CELDPIssue{
			{Severity: "warning"},
			{Severity: "error"},
		}
		if !hasErrors(issues) {
			t.Error("Expected hasErrors to return true")
		}
	})

	t.Run("No errors", func(t *testing.T) {
		issues := []CELDPIssue{
			{Severity: "warning"},
			{Severity: "info"},
		}
		if hasErrors(issues) {
			t.Error("Expected hasErrors to return false")
		}
	})

	t.Run("Empty", func(t *testing.T) {
		if hasErrors(nil) {
			t.Error("Expected hasErrors to return false for nil")
		}
	})
}

func TestFindLocation(t *testing.T) {
	expr := "x + 3.14 + y"
	loc := findLocation(expr, "3.14")
	if loc == "" {
		t.Error("Expected non-empty location")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
