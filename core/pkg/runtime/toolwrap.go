// Package runtime — ToolWrapper + ErrorTaxonomy.
//
// Per HELM 2030 Spec §4.7:
//
//	Deterministic tool wrappers: structured output, stable logs,
//	consistent error taxonomy.
package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ErrorCategory classifies tool errors consistently.
type ErrorCategory string

const (
	ErrCatTransient  ErrorCategory = "TRANSIENT"  // Retry may succeed
	ErrCatPermanent  ErrorCategory = "PERMANENT"  // Will never succeed
	ErrCatPermission ErrorCategory = "PERMISSION" // Auth/authz failure
	ErrCatRateLimit  ErrorCategory = "RATE_LIMIT" // Throttled
	ErrCatTimeout    ErrorCategory = "TIMEOUT"    // Timed out
	ErrCatValidation ErrorCategory = "VALIDATION" // Bad input
	ErrCatNotFound   ErrorCategory = "NOT_FOUND"  // Resource missing
	ErrCatInternal   ErrorCategory = "INTERNAL"   // Bug or unexpected
)

// ClassifiedError is an error with taxonomy classification.
type ClassifiedError struct {
	Category  ErrorCategory `json:"category"`
	Code      string        `json:"code"`
	Message   string        `json:"message"`
	Retryable bool          `json:"retryable"`
	ToolName  string        `json:"tool_name"`
}

func (e *ClassifiedError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", e.Category, e.Code, e.Message)
}

// ToolResult is the structured output of a tool call.
type ToolResult struct {
	ToolName   string           `json:"tool_name"`
	Success    bool             `json:"success"`
	Output     interface{}      `json:"output,omitempty"`
	Error      *ClassifiedError `json:"error,omitempty"`
	Duration   time.Duration    `json:"duration"`
	InputHash  string           `json:"input_hash"`
	OutputHash string           `json:"output_hash"`
	Timestamp  time.Time        `json:"timestamp"`
}

// ToolWrapper wraps a tool function with deterministic execution envelope.
type ToolWrapper struct {
	mu      sync.Mutex
	name    string
	timeout time.Duration
	results []ToolResult
	clock   func() time.Time
}

// NewToolWrapper creates a new wrapper.
func NewToolWrapper(name string, timeout time.Duration) *ToolWrapper {
	return &ToolWrapper{
		name:    name,
		timeout: timeout,
		clock:   time.Now,
	}
}

// WithClock overrides clock for testing.
func (w *ToolWrapper) WithClock(clock func() time.Time) *ToolWrapper {
	w.clock = clock
	return w
}

// Execute runs a tool function with structured output and error classification.
func (w *ToolWrapper) Execute(input interface{}, fn func(interface{}) (interface{}, error)) *ToolResult {
	w.mu.Lock()
	start := w.clock()
	w.mu.Unlock()

	inputStr := fmt.Sprintf("%v", input)
	inputH := sha256.Sum256([]byte(inputStr))

	output, err := fn(input)

	w.mu.Lock()
	defer w.mu.Unlock()

	end := w.clock()
	duration := end.Sub(start)

	result := &ToolResult{
		ToolName:  w.name,
		InputHash: "sha256:" + hex.EncodeToString(inputH[:]),
		Duration:  duration,
		Timestamp: start,
	}

	if err != nil {
		result.Success = false
		result.Error = ClassifyError(w.name, err)
		result.OutputHash = ""
	} else {
		result.Success = true
		result.Output = output
		outStr := fmt.Sprintf("%v", output)
		outH := sha256.Sum256([]byte(outStr))
		result.OutputHash = "sha256:" + hex.EncodeToString(outH[:])
	}

	// Check timeout
	if duration > w.timeout {
		result.Success = false
		result.Error = &ClassifiedError{
			Category: ErrCatTimeout, Code: "TOOL_TIMEOUT", Retryable: true, ToolName: w.name,
			Message: fmt.Sprintf("exceeded %v", w.timeout),
		}
	}

	w.results = append(w.results, *result)
	return result
}

// Results returns all recorded results.
func (w *ToolWrapper) Results() []ToolResult {
	w.mu.Lock()
	defer w.mu.Unlock()
	r := make([]ToolResult, len(w.results))
	copy(r, w.results)
	return r
}

// ClassifyError maps a raw error to the taxonomy.
func ClassifyError(toolName string, err error) *ClassifiedError {
	msg := err.Error()

	// Classification heuristics
	switch {
	case contains(msg, "timeout"):
		return &ClassifiedError{ErrCatTimeout, "TIMEOUT", msg, true, toolName}
	case contains(msg, "rate limit") || contains(msg, "throttl"):
		return &ClassifiedError{ErrCatRateLimit, "RATE_LIMITED", msg, true, toolName}
	case contains(msg, "permission") || contains(msg, "forbidden") || contains(msg, "unauthorized"):
		return &ClassifiedError{ErrCatPermission, "AUTH_FAILURE", msg, false, toolName}
	case contains(msg, "not found"):
		return &ClassifiedError{ErrCatNotFound, "NOT_FOUND", msg, false, toolName}
	case contains(msg, "invalid") || contains(msg, "validation"):
		return &ClassifiedError{ErrCatValidation, "VALIDATION", msg, false, toolName}
	case contains(msg, "temporary") || contains(msg, "retry"):
		return &ClassifiedError{ErrCatTransient, "TRANSIENT", msg, true, toolName}
	default:
		return &ClassifiedError{ErrCatInternal, "INTERNAL", msg, false, toolName}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstring(s, sub))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
