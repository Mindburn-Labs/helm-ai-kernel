// Package kernel provides ErrorIR construction per Normative Addendum 8.5.X.
package kernel

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ErrorClassification defines the retry behavior for errors.
type ErrorClassification string

const (
	// ErrorClassRetryable indicates a transient failure that may succeed on retry.
	ErrorClassRetryable ErrorClassification = "RETRYABLE"
	// ErrorClassNonRetryable indicates a permanent failure.
	ErrorClassNonRetryable ErrorClassification = "NON_RETRYABLE"
	// ErrorClassIdempotentSafe indicates the operation was already completed.
	ErrorClassIdempotentSafe ErrorClassification = "IDEMPOTENT_SAFE"
	// ErrorClassCompensationRequired indicates partial failure requiring compensation.
	ErrorClassCompensationRequired ErrorClassification = "COMPENSATION_REQUIRED"
)

// ErrorIR represents a canonical error per RFC 9457 + HELM extensions.
type ErrorIR struct {
	// RFC 9457 standard fields
	Type     string `json:"type"`               // URI identifying the problem type
	Title    string `json:"title"`              // Human-readable summary
	Status   int    `json:"status"`             // HTTP status code
	Detail   string `json:"detail,omitempty"`   // Human-readable explanation
	Instance string `json:"instance,omitempty"` // URI for this occurrence

	// HELM extensions
	HELM HELMErrorExtensions `json:"helm"`
}

// HELMErrorExtensions contains HELM-specific error fields.
type HELMErrorExtensions struct {
	ErrorCode           string              `json:"error_code"`
	Namespace           string              `json:"namespace"`
	Classification      ErrorClassification `json:"classification"`
	CanonicalCauseChain []ErrorCause        `json:"canonical_cause_chain,omitempty"`
}

// ErrorCause represents a single cause in the error chain.
type ErrorCause struct {
	ErrorCode string `json:"error_code"`
	At        string `json:"at"` // JSON Pointer path
}

// Core error codes per Addendum 8.5.X.3
const (
	// Validation errors
	ErrCodeSchemaMismatch = "HELM/CORE/VALIDATION/SCHEMA_MISMATCH"
	ErrCodeCSNFViolation  = "HELM/CORE/VALIDATION/CSNF_VIOLATION"

	// Auth errors
	ErrCodeUnauthorized = "HELM/CORE/AUTH/UNAUTHORIZED"
	ErrCodeForbidden    = "HELM/CORE/AUTH/FORBIDDEN"

	// Effect errors
	ErrCodeTimeout       = "HELM/CORE/EFFECT/TIMEOUT"
	ErrCodeUpstreamError = "HELM/CORE/EFFECT/UPSTREAM_ERROR"
	ErrCodeIdempotency   = "HELM/CORE/EFFECT/IDEMPOTENCY_CONFLICT"

	// Policy errors
	ErrCodePolicyDenied = "HELM/CORE/POLICY/DENIED"

	// Resource errors
	ErrCodeNotFound = "HELM/CORE/RESOURCE/NOT_FOUND"
	ErrCodeConflict = "HELM/CORE/RESOURCE/CONFLICT"

	// CEL-DP errors
	ErrCodeCELEvaluation   = "HELM/CORE/CEL_DP/EVALUATION_ERROR"
	ErrCodeCELValidation   = "HELM/CORE/CEL_DP/VALIDATION_FAILED"
	ErrCodeCELCostExceeded = "HELM/CORE/CEL_DP/COST_EXCEEDED"
	ErrCodeCELTimeout      = "HELM/CORE/CEL_DP/TIMEOUT"
)

// ErrorIRBuilder provides a fluent interface for building ErrorIR.
type ErrorIRBuilder struct {
	err ErrorIR
}

// NewErrorIR creates a new ErrorIR builder.
func NewErrorIR(errorCode string) *ErrorIRBuilder {
	namespace := extractNamespace(errorCode)
	classification := classifyError(errorCode)

	return &ErrorIRBuilder{
		err: ErrorIR{
			Type:   fmt.Sprintf("https://helm.org/errors/%s", strings.ToLower(strings.ReplaceAll(errorCode, "/", "-"))),
			Status: classificationToStatus(classification),
			HELM: HELMErrorExtensions{
				ErrorCode:      errorCode,
				Namespace:      namespace,
				Classification: classification,
			},
		},
	}
}

// WithTitle sets the error title.
func (b *ErrorIRBuilder) WithTitle(title string) *ErrorIRBuilder {
	b.err.Title = title
	return b
}

// WithDetail sets the error detail.
func (b *ErrorIRBuilder) WithDetail(detail string) *ErrorIRBuilder {
	b.err.Detail = detail
	return b
}

// WithStatus overrides the HTTP status code.
func (b *ErrorIRBuilder) WithStatus(status int) *ErrorIRBuilder {
	b.err.Status = status
	return b
}

// WithInstance sets the instance URI.
func (b *ErrorIRBuilder) WithInstance(instance string) *ErrorIRBuilder {
	b.err.Instance = instance
	return b
}

// WithClassification overrides the error classification.
func (b *ErrorIRBuilder) WithClassification(c ErrorClassification) *ErrorIRBuilder {
	b.err.HELM.Classification = c
	return b
}

// WithCause adds a cause to the error chain.
func (b *ErrorIRBuilder) WithCause(errorCode, at string) *ErrorIRBuilder {
	b.err.HELM.CanonicalCauseChain = append(b.err.HELM.CanonicalCauseChain, ErrorCause{
		ErrorCode: errorCode,
		At:        at,
	})
	return b
}

// Build returns the constructed ErrorIR.
func (b *ErrorIRBuilder) Build() ErrorIR {
	return b.err
}

// extractNamespace extracts the namespace from an error code.
func extractNamespace(code string) string {
	parts := strings.Split(code, "/")
	if len(parts) >= 2 {
		return parts[1] // CORE, ADAPTER/<id>, PACK/<id>
	}
	return "UNKNOWN"
}

// classifyError determines the classification based on error code.
func classifyError(code string) ErrorClassification {
	// Default classifications based on error code patterns
	switch {
	case strings.Contains(code, "/TIMEOUT"):
		return ErrorClassRetryable
	case strings.Contains(code, "/UPSTREAM_ERROR"):
		return ErrorClassRetryable
	case strings.Contains(code, "/CONFLICT"):
		return ErrorClassRetryable
	case strings.Contains(code, "/IDEMPOTENCY"):
		return ErrorClassIdempotentSafe
	case strings.Contains(code, "/VALIDATION/"):
		return ErrorClassNonRetryable
	case strings.Contains(code, "/AUTH/"):
		return ErrorClassNonRetryable
	case strings.Contains(code, "/POLICY/"):
		return ErrorClassNonRetryable
	default:
		return ErrorClassNonRetryable
	}
}

// classificationToStatus maps classification to HTTP status.
func classificationToStatus(c ErrorClassification) int {
	switch c {
	case ErrorClassRetryable:
		return 503 // Service Unavailable
	case ErrorClassNonRetryable:
		return 400 // Bad Request
	case ErrorClassIdempotentSafe:
		return 200 // OK (already done)
	case ErrorClassCompensationRequired:
		return 500 // Internal Server Error
	default:
		return 500
	}
}

// BackoffParams contains parameters for deterministic backoff calculation.
type BackoffParams struct {
	PolicyID     string
	AdapterID    string
	EffectID     string
	AttemptIndex int
	EnvSnapHash  string
}

// BackoffPolicy defines retry backoff configuration.
type BackoffPolicy struct {
	PolicyID    string `json:"policy_id"`
	BaseMs      int64  `json:"base_ms"`
	MaxMs       int64  `json:"max_ms"`
	MaxJitterMs int64  `json:"max_jitter_ms"`
	MaxAttempts int    `json:"max_attempts"`
}

// DefaultBackoffPolicy returns the default backoff policy.
func DefaultBackoffPolicy() BackoffPolicy {
	return BackoffPolicy{
		PolicyID:    "default-backoff",
		BaseMs:      100,
		MaxMs:       30000,
		MaxJitterMs: 1000,
		MaxAttempts: 5,
	}
}

// ComputeBackoff calculates deterministic retry delay per Addendum 8.5.X.5.
func ComputeBackoff(params BackoffParams, policy BackoffPolicy) time.Duration {
	// 1. Compute base delay with exponential backoff
	baseDelay := policy.BaseMs * (1 << params.AttemptIndex)

	// 2. Cap at maximum
	if baseDelay > policy.MaxMs {
		baseDelay = policy.MaxMs
	}

	// 3. Add deterministic jitter (NOT wall-clock random)
	jitter := ComputeDeterministicJitter(params, policy.MaxJitterMs)

	return time.Duration(baseDelay+jitter) * time.Millisecond
}

// ComputeDeterministicJitter computes jitter based on stable inputs.
// Per Addendum 8.5.X.5: Jitter MUST be deterministic, not wall-clock random.
func ComputeDeterministicJitter(params BackoffParams, maxJitterMs int64) int64 {
	if maxJitterMs <= 0 {
		return 0
	}

	// Create deterministic seed from inputs
	seed := fmt.Sprintf("%s:%s:%s:%d:%s",
		params.PolicyID,
		params.AdapterID,
		params.EffectID,
		params.AttemptIndex,
		params.EnvSnapHash,
	)

	hash := sha256.Sum256([]byte(seed))
	// Use first 8 bytes as jitter basis
	jitterBasis := binary.BigEndian.Uint64(hash[:8])

	// Scale to jitter range
	return int64(jitterBasis % uint64(maxJitterMs)) //nolint:gosec // Safe modulo
}

// RetryPlan represents a pre-committed retry schedule.
type RetryPlan struct {
	RetryPlanID string         `json:"retry_plan_id"`
	EffectID    string         `json:"effect_id"`
	PolicyID    string         `json:"policy_id"`
	Schedule    []RetryAttempt `json:"schedule"`
	MaxAttempts int            `json:"max_attempts"`
	ExpiresAt   time.Time      `json:"expires_at"`
	CreatedAt   time.Time      `json:"created_at"`
}

// RetryAttempt represents a single scheduled attempt.
type RetryAttempt struct {
	AttemptIndex int       `json:"attempt_index"`
	DelayMs      int64     `json:"delay_ms"`
	ScheduledAt  time.Time `json:"scheduled_at"`
}

// CreateRetryPlan generates a pre-committed retry schedule.
// Per Addendum 8.5.X.6: Retry schedule MUST be committed before attempts.
func CreateRetryPlan(effectID string, policy BackoffPolicy, envSnapHash string, startTime time.Time) RetryPlan {
	schedule := make([]RetryAttempt, policy.MaxAttempts)
	currentTime := startTime

	for i := 0; i < policy.MaxAttempts; i++ {
		params := BackoffParams{
			PolicyID:     policy.PolicyID,
			EffectID:     effectID,
			AttemptIndex: i,
			EnvSnapHash:  envSnapHash,
		}

		delay := ComputeBackoff(params, policy)
		currentTime = currentTime.Add(delay)

		schedule[i] = RetryAttempt{
			AttemptIndex: i,
			DelayMs:      delay.Milliseconds(),
			ScheduledAt:  currentTime,
		}
	}

	// Generate content-addressed plan ID
	planID := generateRetryPlanID(effectID, policy.PolicyID, startTime, envSnapHash)

	return RetryPlan{
		RetryPlanID: planID,
		EffectID:    effectID,
		PolicyID:    policy.PolicyID,
		Schedule:    schedule,
		MaxAttempts: policy.MaxAttempts,
		ExpiresAt:   schedule[len(schedule)-1].ScheduledAt.Add(time.Minute), // 1 min grace
		CreatedAt:   startTime,
	}
}

func generateRetryPlanID(effectID, policyID string, startTime time.Time, envSnapHash string) string {
	input := fmt.Sprintf("%s:%s:%s:%s", effectID, policyID, startTime.Format(time.RFC3339Nano), envSnapHash)
	hash := sha256.Sum256([]byte(input))
	return "rp_" + hex.EncodeToString(hash[:8])
}

// CompareErrors implements deterministic error selection.
// Per Addendum 8.5.X.4: Return error with smallest (error_code, path) tuple.
func CompareErrors(a, b ErrorIR) int {
	// First compare by error code
	if cmp := strings.Compare(a.HELM.ErrorCode, b.HELM.ErrorCode); cmp != 0 {
		return cmp
	}

	// Then compare by first cause path (if available)
	aPath := ""
	bPath := ""
	if len(a.HELM.CanonicalCauseChain) > 0 {
		aPath = a.HELM.CanonicalCauseChain[0].At
	}
	if len(b.HELM.CanonicalCauseChain) > 0 {
		bPath = b.HELM.CanonicalCauseChain[0].At
	}

	return strings.Compare(aPath, bPath)
}

// SelectCanonicalError selects the canonical error from multiple candidates.
func SelectCanonicalError(errors []ErrorIR) ErrorIR {
	if len(errors) == 0 {
		return ErrorIR{}
	}
	if len(errors) == 1 {
		return errors[0]
	}

	canonical := errors[0]
	for _, err := range errors[1:] {
		if CompareErrors(err, canonical) < 0 {
			canonical = err
		}
	}
	return canonical
}
