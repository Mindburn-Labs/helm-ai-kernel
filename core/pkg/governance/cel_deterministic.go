// Package governance provides the Deterministic CEL Profile (cel-dp-v1).
// Per HELM Normative Addendum v1.5 Section B - Deterministic CEL Profile.
package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// CELDPProfileID is the profile identifier for deterministic CEL.
const CELDPProfileID = "cel-dp-v1"

// CELDPErrorCode defines the fixed error code registry.
// Per Section B.6: Error codes from a fixed registry.
type CELDPErrorCode string

const (
	CELDPErrorTypeError  CELDPErrorCode = "CEL_TYPE_ERROR"
	CELDPErrorDivZero    CELDPErrorCode = "CEL_DIV_ZERO"
	CELDPErrorOverflow   CELDPErrorCode = "CEL_OVERFLOW"
	CELDPErrorUndefined  CELDPErrorCode = "CEL_UNDEFINED"
	CELDPErrorInvalidArg CELDPErrorCode = "CEL_INVALID_ARG"
	CELDPErrorInternal   CELDPErrorCode = "CEL_INTERNAL"
)

// CELDPOutcome represents the evaluation outcome.
type CELDPOutcome string

const (
	CELDPOutcomeValue CELDPOutcome = "VALUE"
	CELDPOutcomeError CELDPOutcome = "ERROR"
)

// CELDPError represents a deterministic CEL error.
// Per Section B.6: Error model with code, message_hash, and span.
type CELDPError struct {
	Code        CELDPErrorCode `json:"code"`
	MessageHash string         `json:"message_hash"` // Hash of normalized message, not raw
	Span        *CELDPSpan     `json:"span,omitempty"`
}

// CELDPSpan represents an optional source span for errors.
type CELDPSpan struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// CELDPResult represents the result of a CEL-DP evaluation.
type CELDPResult struct {
	ProfileID string       `json:"cel_profile_id"`
	Outcome   CELDPOutcome `json:"cel_outcome"`
	Value     any          `json:"value,omitempty"`
	Error     *CELDPError  `json:"cel_error,omitempty"`
	TraceHash string       `json:"trace_hash,omitempty"`
}

// CELDPValidator validates CEL expressions for cel-dp-v1 compliance.
type CELDPValidator struct {
	// BannedFunctions lists functions that are forbidden in cel-dp-v1.
	BannedFunctions map[string]bool
	// BannedTypes lists types that are forbidden (double/float).
	BannedTypes map[string]bool
}

// NewCELDPValidator creates a new CEL-DP validator.
func NewCELDPValidator() *CELDPValidator {
	return &CELDPValidator{
		BannedFunctions: map[string]bool{
			// Per Section B.4: Forbidden features
			"now":               true,
			"timestamp":         true,
			"duration":          true,
			"random":            true,
			"uuid":              true,
			"matches":           true,  // Regex - forbidden by default
			"contains":          false, // String contains is OK
			"startsWith":        false,
			"endsWith":          false,
			"getDate":           true,
			"getDayOfMonth":     true,
			"getDayOfWeek":      true,
			"getDayOfYear":      true,
			"getFullYear":       true,
			"getHours":          true,
			"getMilliseconds":   true,
			"getMinutes":        true,
			"getMonth":          true,
			"getSeconds":        true,
			"getTimezoneOffset": true,
		},
		BannedTypes: map[string]bool{
			"double": true,
			"float":  true,
		},
	}
}

// ValidationIssue represents a compliance issue in a CEL expression.
type ValidationIssue struct {
	Type    string     `json:"type"`    // "banned_function", "banned_type", "nondeterministic"
	Name    string     `json:"name"`    // The offending identifier
	Message string     `json:"message"` // Human-readable description
	Span    *CELDPSpan `json:"span,omitempty"`
}

// ValidateExpression checks a CEL expression for cel-dp-v1 compliance.
// Per Section B.3-B.4: Allowed types and Forbidden features.
func (v *CELDPValidator) ValidateExpression(expr string) []ValidationIssue {
	issues := []ValidationIssue{}

	// Check for banned function calls
	for fn := range v.BannedFunctions {
		if v.BannedFunctions[fn] && containsFunction(expr, fn) {
			issues = append(issues, ValidationIssue{
				Type:    "banned_function",
				Name:    fn,
				Message: fmt.Sprintf("function %q is forbidden in cel-dp-v1", fn),
			})
		}
	}

	// Check for banned types
	for typ := range v.BannedTypes {
		if containsType(expr, typ) {
			issues = append(issues, ValidationIssue{
				Type:    "banned_type",
				Name:    typ,
				Message: fmt.Sprintf("type %q is forbidden in cel-dp-v1; use int or uint", typ),
			})
		}
	}

	// Check for dynamic type operations
	dynamicOps := []string{"type(", "dyn("}
	for _, op := range dynamicOps {
		if strings.Contains(expr, op) {
			issues = append(issues, ValidationIssue{
				Type:    "nondeterministic",
				Name:    op,
				Message: fmt.Sprintf("dynamic operation %q may vary by implementation", op),
			})
		}
	}

	return issues
}

// containsFunction checks if an expression contains a function call.
func containsFunction(expr, funcName string) bool {
	// Pattern: funcName followed by (
	pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(funcName) + `\s*\(`)
	return pattern.MatchString(expr)
}

// containsType checks if an expression references a type.
func containsType(expr, typeName string) bool {
	// Pattern: type keyword followed by the type name
	pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(typeName) + `\b`)
	return pattern.MatchString(expr)
}

// HashErrorMessage produces a deterministic hash of an error message.
// Per Section B.6: message_hash (hash of normalized message, not raw).
func HashErrorMessage(message string) string {
	// Normalize: lowercase, trim whitespace, normalize spaces
	normalized := strings.ToLower(strings.TrimSpace(message))
	normalized = regexp.MustCompile(`\s+`).ReplaceAllString(normalized, " ")

	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:8]) // First 8 bytes for brevity
}

// NewCELDPError creates a new CEL-DP compliant error.
func NewCELDPError(code CELDPErrorCode, message string, span *CELDPSpan) *CELDPError {
	return &CELDPError{
		Code:        code,
		MessageHash: HashErrorMessage(message),
		Span:        span,
	}
}

// CELDPEvaluationContext provides deterministic inputs for CEL evaluation.
// Per Section B.4: No reliance on environment or nondeterministic sources.
type CELDPEvaluationContext struct {
	// DecisionTime is the explicit time to use (not now())
	DecisionTime int64 `json:"decision_time"` // Unix epoch seconds

	// Variables are the input variables for evaluation
	Variables map[string]any `json:"variables"`
}

// CELDPTraceEntry represents a single step in an evaluation trace.
type CELDPTraceEntry struct {
	Step       int    `json:"step"`
	Expression string `json:"expression"`
	ResultHash string `json:"result_hash"`
}

// ComputeTraceHash produces a deterministic hash of a trace.
// Per Section B.6: Traces MUST be canonical and not include timing.
func ComputeTraceHash(entries []CELDPTraceEntry) string {
	if len(entries) == 0 {
		return ""
	}

	// Hash the concatenation of step+expression+result_hash
	var builder strings.Builder
	for _, entry := range entries {
		_, _ = fmt.Fprintf(&builder, "%d:%s:%s;", entry.Step, entry.Expression, entry.ResultHash)
	}

	hash := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(hash[:])
}

// CELDPConfig configures the deterministic CEL evaluator.
type CELDPConfig struct {
	// StrictMode rejects any expression that uses forbidden features.
	StrictMode bool `json:"strict_mode"`

	// AllowedFunctions is an optional allowlist (if empty, uses default).
	AllowedFunctions []string `json:"allowed_functions,omitempty"`
}

// DefaultCELDPConfig removed - was dead code

// CELDPExpressionInfo contains metadata about a validated expression.
type CELDPExpressionInfo struct {
	Expression string            `json:"expression"`
	ProfileID  string            `json:"cel_profile_id"`
	Valid      bool              `json:"valid"`
	Issues     []ValidationIssue `json:"issues,omitempty"`
	InputVars  []string          `json:"input_vars,omitempty"`
	ReturnType string            `json:"return_type,omitempty"`
}

// ValidateAndAnalyze validates and analyzes a CEL expression.
func (v *CELDPValidator) ValidateAndAnalyze(expr string) CELDPExpressionInfo {
	issues := v.ValidateExpression(expr)

	return CELDPExpressionInfo{
		Expression: expr,
		ProfileID:  CELDPProfileID,
		Valid:      len(issues) == 0,
		Issues:     issues,
	}
}
