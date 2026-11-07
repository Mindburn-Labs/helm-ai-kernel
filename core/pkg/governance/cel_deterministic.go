// Package governance provides the Deterministic CEL Profile (cel-dp-v1).
// Per HELM Normative Addendum v1.5 Section B - Deterministic CEL Profile.
package governance

import ()

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

// ValidationIssue represents a compliance issue in a CEL expression.
type ValidationIssue struct {
	Type    string     `json:"type"`    // "banned_function", "banned_type", "nondeterministic"
	Name    string     `json:"name"`    // The offending identifier
	Message string     `json:"message"` // Human-readable description
	Span    *CELDPSpan `json:"span,omitempty"`
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
