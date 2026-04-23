// Package scheduler provides automation scheduling for the HELM runtime.
// Schedules are fail-closed: invalid or ambiguous specs are rejected at registration time.
package scheduler

import (
	"errors"
	"fmt"
	"time"
)

// ScheduleKind identifies the expression language used in a ScheduleSpec.
type ScheduleKind string

const (
	// ScheduleCron uses a standard 5-field cron expression.
	ScheduleCron ScheduleKind = "cron"
	// ScheduleRRULE uses the supported iCalendar RRULE subset.
	ScheduleRRULE ScheduleKind = "rrule"
)

// CatchupPolicy controls how the scheduler handles missed fire times after downtime.
type CatchupPolicy string

const (
	// CatchupNone discards all missed fires.
	CatchupNone CatchupPolicy = "none"
	// CatchupSingle fires once for the most recent missed slot.
	CatchupSingle CatchupPolicy = "single"
	// CatchupBackfill fires once for every missed slot in order.
	CatchupBackfill CatchupPolicy = "backfill"
)

// RetryPolicy controls retry behaviour for failed dispatch attempts.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts (1 = no retries).
	MaxAttempts int `json:"max_attempts"`
	// BackoffMode is one of "exponential", "linear", or "fixed".
	BackoffMode string `json:"backoff_mode"`
	// MinBackoffS is the minimum backoff interval in seconds.
	MinBackoffS int `json:"min_backoff_s"`
	// MaxBackoffS is the maximum backoff interval in seconds.
	MaxBackoffS int `json:"max_backoff_s"`
}

// ScheduleSpec is the canonical representation of an automation schedule.
type ScheduleSpec struct {
	// ScheduleID is a unique, stable identifier for this schedule.
	ScheduleID string `json:"schedule_id"`
	// TenantID scopes the schedule to a tenant.
	TenantID string `json:"tenant_id"`
	// Kind selects the expression language.
	Kind ScheduleKind `json:"kind"`
	// Expression is the cron or RRULE expression.
	Expression string `json:"expression"`
	// Timezone is an IANA timezone name (e.g. "America/New_York"). Empty defaults to UTC.
	Timezone string `json:"timezone"`
	// CatchupPolicy controls missed-fire behaviour.
	CatchupPolicy CatchupPolicy `json:"catchup_policy"`
	// MaxConcurrency is the maximum number of concurrent in-flight triggers (0 = unlimited).
	MaxConcurrency int `json:"max_concurrency"`
	// JitterWindowMs adds up to this many milliseconds of random delay after the nominal fire time.
	JitterWindowMs int `json:"jitter_window_ms"`
	// Retry controls retry behaviour for failed dispatch attempts.
	Retry RetryPolicy `json:"retry"`
	// Enabled gates whether the scheduler will generate triggers.
	Enabled bool `json:"enabled"`
	// IntentTemplateID references the intent template to dispatch on each trigger.
	IntentTemplateID string `json:"intent_template_id"`
}

// Sentinel errors returned by Validate.
var (
	ErrEmptyScheduleID        = errors.New("schedule_id must not be empty")
	ErrEmptyTenantID          = errors.New("tenant_id must not be empty")
	ErrEmptyIntentTemplateID  = errors.New("intent_template_id must not be empty")
	ErrUnknownKind            = errors.New("unknown schedule kind")
	ErrEmptyExpression        = errors.New("expression must not be empty")
	ErrUnknownCatchupPolicy   = errors.New("unknown catchup policy")
	ErrNegativeMaxConcurrency = errors.New("max_concurrency must be >= 0")
	ErrNegativeJitterWindow   = errors.New("jitter_window_ms must be >= 0")
	ErrInvalidRetryPolicy     = errors.New("invalid retry policy")
	ErrUnknownTimezone        = errors.New("unknown timezone")
)

// Validate performs fail-closed validation of a ScheduleSpec.
// It returns the first validation error encountered, or nil if the spec is valid.
func Validate(spec ScheduleSpec) error {
	if spec.ScheduleID == "" {
		return ErrEmptyScheduleID
	}
	if spec.TenantID == "" {
		return ErrEmptyTenantID
	}
	if spec.IntentTemplateID == "" {
		return ErrEmptyIntentTemplateID
	}
	if spec.Kind != ScheduleCron && spec.Kind != ScheduleRRULE {
		return fmt.Errorf("%w: %q", ErrUnknownKind, spec.Kind)
	}
	if spec.Expression == "" {
		return ErrEmptyExpression
	}
	switch spec.CatchupPolicy {
	case CatchupNone, CatchupSingle, CatchupBackfill:
		// valid
	default:
		return fmt.Errorf("%w: %q", ErrUnknownCatchupPolicy, spec.CatchupPolicy)
	}
	if spec.MaxConcurrency < 0 {
		return ErrNegativeMaxConcurrency
	}
	if spec.JitterWindowMs < 0 {
		return ErrNegativeJitterWindow
	}
	if err := validateRetryPolicy(spec.Retry); err != nil {
		return err
	}
	// Validate timezone (empty == UTC is acceptable).
	if spec.Timezone != "" {
		if _, err := time.LoadLocation(spec.Timezone); err != nil {
			return fmt.Errorf("%w: %q", ErrUnknownTimezone, spec.Timezone)
		}
	}
	// Parse the expression to catch syntax errors early.
	switch spec.Kind {
	case ScheduleCron:
		if _, err := ParseCron(spec.Expression); err != nil {
			return fmt.Errorf("invalid cron expression: %w", err)
		}
	case ScheduleRRULE:
		if err := ParseRRULE(spec.Expression); err != nil {
			return fmt.Errorf("invalid rrule expression: %w", err)
		}
	}
	return nil
}

// validateRetryPolicy checks the RetryPolicy sub-struct.
func validateRetryPolicy(r RetryPolicy) error {
	if r.MaxAttempts < 0 {
		return fmt.Errorf("%w: max_attempts must be >= 0", ErrInvalidRetryPolicy)
	}
	switch r.BackoffMode {
	case "", "exponential", "linear", "fixed":
		// valid
	default:
		return fmt.Errorf("%w: backoff_mode %q is not one of exponential, linear, fixed", ErrInvalidRetryPolicy, r.BackoffMode)
	}
	if r.MinBackoffS < 0 {
		return fmt.Errorf("%w: min_backoff_s must be >= 0", ErrInvalidRetryPolicy)
	}
	if r.MaxBackoffS < 0 {
		return fmt.Errorf("%w: max_backoff_s must be >= 0", ErrInvalidRetryPolicy)
	}
	if r.MaxBackoffS > 0 && r.MaxBackoffS < r.MinBackoffS {
		return fmt.Errorf("%w: max_backoff_s must be >= min_backoff_s", ErrInvalidRetryPolicy)
	}
	return nil
}
