// Package kernel provides CEL Deterministic Profile (CEL-DP v1) per Addendum 6.9.
package kernel

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
)

// CELDPTier defines the CEL usage tier.
type CELDPTier int

const (
	// CELDPTierKernelCritical requires CEL-DP v1 compliance.
	CELDPTierKernelCritical CELDPTier = 0
	// CELDPTierNonCritical allows unrestricted CEL.
	CELDPTierNonCritical CELDPTier = 1
)

// CELDPCostBudget defines execution limits for CEL-DP expressions.
type CELDPCostBudget struct {
	MaxExpressionSize  int   `json:"max_expression_size"`  // Max AST nodes
	MaxMacroExpansions int   `json:"max_macro_expansions"` // Max macro expansions
	MaxNestingDepth    int   `json:"max_nesting_depth"`    // Max expression nesting
	MaxEvaluationCost  int64 `json:"max_evaluation_cost"`  // Max runtime cost units
	HardTimeoutMs      int   `json:"hard_timeout_ms"`      // Hard timeout in milliseconds
}

// DefaultCELDPBudget returns the default cost budget for CEL-DP.
func DefaultCELDPBudget() CELDPCostBudget {
	return CELDPCostBudget{
		MaxExpressionSize:  1000,
		MaxMacroExpansions: 100,
		MaxNestingDepth:    20,
		MaxEvaluationCost:  100000,
		HardTimeoutMs:      100,
	}
}

// CELDPIssue represents a validation issue for CEL-DP expressions.
type CELDPIssue struct {
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
	Location string `json:"location,omitempty"` // Position in expression
	Severity string `json:"severity"`           // "error" or "warning"
}

// CELDPValidationResult contains the results of CEL-DP validation.
type CELDPValidationResult struct {
	Valid  bool         `json:"valid"`
	Issues []CELDPIssue `json:"issues"`
	Tier   CELDPTier    `json:"tier"`
}

// CEL-DP Rule IDs per Addendum 6.9.6
const (
	CELDPRuleNoFloats            = "CEL-DP-001"
	CELDPRuleNoTimeTypes         = "CEL-DP-002"
	CELDPRuleNoNowAccess         = "CEL-DP-003"
	CELDPRuleNoMapIterOrder      = "CEL-DP-004"
	CELDPRuleNoEvalOrderAmbig    = "CEL-DP-005"
	CELDPRuleNoUnboundedRecurse  = "CEL-DP-006"
	CELDPRuleExpressionSizeLimit = "CEL-DP-007"
)

// CELDPValidator validates CEL expressions for CEL-DP compliance.
type CELDPValidator struct {
	budget CELDPCostBudget
}

// NewCELDPValidator creates a new CEL-DP validator.
func NewCELDPValidator() *CELDPValidator {
	return &CELDPValidator{
		budget: DefaultCELDPBudget(),
	}
}

// WithBudget sets a custom cost budget.
func (v *CELDPValidator) WithBudget(budget CELDPCostBudget) *CELDPValidator {
	v.budget = budget
	return v
}

// Validate checks if a CEL expression is CEL-DP v1 compliant.
// Per Addendum 6.9.3: All kernel-critical CEL expressions MUST pass this validation.
func (v *CELDPValidator) Validate(expr string) CELDPValidationResult {
	result := CELDPValidationResult{
		Valid:  true,
		Issues: []CELDPIssue{},
		Tier:   CELDPTierKernelCritical,
	}

	// Check for forbidden constructs via static analysis
	v.checkNoFloats(expr, &result)
	v.checkNoTimeAccess(expr, &result)
	v.checkNoMapIterationDependence(expr, &result)
	v.checkExpressionSize(expr, &result)
	v.checkNestingDepth(expr, &result)

	result.Valid = len(result.Issues) == 0 || !hasErrors(result.Issues)
	return result
}

// checkNoFloats detects floating-point type usage.
func (v *CELDPValidator) checkNoFloats(expr string, result *CELDPValidationResult) {
	// Static analysis for double/float literals or operations
	// This is a simplified check - full implementation would use CEL AST
	floatPatterns := []string{
		// Decimal literals
		".0", ".1", ".2", ".3", ".4", ".5", ".6", ".7", ".8", ".9",
		// Double type annotations
		"double(", "float(",
	}

	for _, pattern := range floatPatterns {
		if strings.Contains(expr, pattern) {
			// Check if it's actually a float literal, not a method call
			if isFloatLiteral(expr, pattern) {
				result.Issues = append(result.Issues, CELDPIssue{
					RuleID:   CELDPRuleNoFloats,
					Message:  "floating-point types are forbidden in CEL-DP v1",
					Location: findLocation(expr, pattern),
					Severity: "error",
				})
				break
			}
		}
	}
}

// checkNoTimeAccess detects time/duration type or now() usage.
func (v *CELDPValidator) checkNoTimeAccess(expr string, result *CELDPValidationResult) {
	forbiddenPatterns := []string{
		"now()",
		"timestamp(",
		"duration(",
		".getFullYear",
		".getMonth",
		".getDate",
		".getHours",
		".getMinutes",
		".getSeconds",
	}

	for _, pattern := range forbiddenPatterns {
		if strings.Contains(expr, pattern) {
			result.Issues = append(result.Issues, CELDPIssue{
				RuleID:   CELDPRuleNoTimeTypes,
				Message:  fmt.Sprintf("time/environment access '%s' is forbidden in CEL-DP v1", pattern),
				Location: findLocation(expr, pattern),
				Severity: "error",
			})
		}
	}
}

// checkNoMapIterationDependence detects map iteration order dependence.
func (v *CELDPValidator) checkNoMapIterationDependence(expr string, result *CELDPValidationResult) {
	// Patterns that depend on map iteration order
	forbiddenPatterns := []string{
		".keys()[0]",
		".values()[0]",
		".keys()[",
		".values()[",
	}

	for _, pattern := range forbiddenPatterns {
		if strings.Contains(expr, pattern) {
			result.Issues = append(result.Issues, CELDPIssue{
				RuleID:   CELDPRuleNoMapIterOrder,
				Message:  fmt.Sprintf("map iteration order dependence '%s' is non-deterministic", pattern),
				Location: findLocation(expr, pattern),
				Severity: "error",
			})
		}
	}
}

// checkExpressionSize validates expression size limit.
func (v *CELDPValidator) checkExpressionSize(expr string, result *CELDPValidationResult) {
	// Simplified size check (full implementation would count AST nodes)
	if len(expr) > v.budget.MaxExpressionSize*10 { // Rough heuristic
		result.Issues = append(result.Issues, CELDPIssue{
			RuleID:   CELDPRuleExpressionSizeLimit,
			Message:  fmt.Sprintf("expression size exceeds limit (%d chars)", len(expr)),
			Severity: "error",
		})
	}
}

// checkNestingDepth validates expression nesting.
func (v *CELDPValidator) checkNestingDepth(expr string, result *CELDPValidationResult) {
	maxDepth := 0
	currentDepth := 0

	for _, c := range expr {
		switch c {
		case '(':
			currentDepth++
			if currentDepth > maxDepth {
				maxDepth = currentDepth
			}
		case ')':
			currentDepth--
		}
	}

	if maxDepth > v.budget.MaxNestingDepth {
		result.Issues = append(result.Issues, CELDPIssue{
			RuleID:   CELDPRuleNoUnboundedRecurse,
			Message:  fmt.Sprintf("nesting depth %d exceeds limit %d", maxDepth, v.budget.MaxNestingDepth),
			Severity: "error",
		})
	}
}

// CELDPResult contains the result of a CEL-DP evaluation.
type CELDPResult struct {
	Value any      `json:"value,omitempty"`
	Error *ErrorIR `json:"error,omitempty"`
}

// CELDPEvaluator provides deterministic CEL evaluation.
type CELDPEvaluator struct {
	validator *CELDPValidator
}

// NewCELDPEvaluator creates a new CEL-DP evaluator.
func NewCELDPEvaluator() *CELDPEvaluator {
	return &CELDPEvaluator{
		validator: NewCELDPValidator(),
	}
}

// Evaluate evaluates a CEL expression with CEL-DP compliance.
// Per Addendum 6.9.7: Validation MUST pass before execution.
func (e *CELDPEvaluator) Evaluate(expr string, input map[string]any) (CELDPResult, error) {
	// 1. Validate expression
	validation := e.validator.Validate(expr)
	if !validation.Valid {
		err := NewErrorIR(ErrCodeCELValidation).
			WithTitle("CEL-DP Validation Failed").
			WithDetail(formatValidationIssues(validation.Issues)).
			Build()
		return CELDPResult{Error: &err}, nil
	}

	// 2. Compile and evaluate with deterministic settings
	// (Actual CEL execution via cel-go)
	result, evalErr := e.evaluateWithCEL(expr, input)
	if evalErr != nil {
		err := NewErrorIR(ErrCodeCELEvaluation).
			WithTitle("CEL Evaluation Error").
			WithDetail(evalErr.Error()).
			Build()
		return CELDPResult{Error: &err}, nil
	}

	return CELDPResult{Value: result}, nil
}

// evaluateWithCEL evaluates a CEL expression using the google/cel-go library.
// It configures the environment to be as deterministic as possible, relying on
// the static validator to catch forbidden constructs (like time/float usage)
// before execution.
func (e *CELDPEvaluator) evaluateWithCEL(expr string, input map[string]any) (any, error) {
	// 1. Create CEL environment
	// We use StdLib() but rely on Validator to forbid non-deterministic parts
	// We also declare standard OrgDNA context variables as dynamic for now.
	env, err := cel.NewEnv(
		cel.StdLib(),
		cel.Variable("modules", cel.ListType(cel.DynType)),
		cel.Variable("meta", cel.DynType),
		cel.Variable("regulation", cel.DynType),
		cel.Variable("phenotype_contract", cel.DynType),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL env: %w", err)
	}

	// 2. Compile expression
	ast, issues := env.Compile(expr)
	if issues.Err() != nil {
		return nil, fmt.Errorf("CEL compile check failed: %w", issues.Err())
	}

	// 3. Create program with deterministic options
	// - CostLimit: Enforce computation budget
	// - InterruptCheckFrequency: Ensure timeout/cancellation is checked
	prog, err := env.Program(ast,
		cel.CostLimit(uint64(e.validator.budget.MaxEvaluationCost)), //nolint:gosec // MaxEvaluationCost is always positive
		cel.InterruptCheckFrequency(100),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	// 5. Evaluate
	// Note: v0.27.0 Eval signature is Eval(vars). We rely on CostLimit for resource bounding.
	val, _, err := prog.Eval(input)
	if err != nil {
		return nil, fmt.Errorf("CEL evaluation failed: %w", err)
	}

	// 6. Convert result to Go native type
	return val.Value(), nil
}

// Helper functions

func isFloatLiteral(expr, pattern string) bool {
	// Simple heuristic: check if pattern is followed by a digit
	idx := strings.Index(expr, pattern)
	if idx < 0 {
		return false
	}
	// Check if it's part of a decimal number
	if pattern[0] == '.' {
		// Check if preceded by a digit
		if idx > 0 && expr[idx-1] >= '0' && expr[idx-1] <= '9' {
			return true
		}
	}
	return strings.Contains(pattern, "(") // Type conversions
}

func findLocation(expr, pattern string) string {
	idx := strings.Index(expr, pattern)
	if idx < 0 {
		return ""
	}
	return fmt.Sprintf("char %d", idx)
}

func hasErrors(issues []CELDPIssue) bool {
	for _, issue := range issues {
		if issue.Severity == "error" {
			return true
		}
	}
	return false
}

func formatValidationIssues(issues []CELDPIssue) string {
	var parts []string
	for _, issue := range issues {
		parts = append(parts, fmt.Sprintf("[%s] %s", issue.RuleID, issue.Message))
	}
	return strings.Join(parts, "; ")
}
