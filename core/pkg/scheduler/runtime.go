package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// TriggerDecision is the output of the scheduler for a single schedule that is due.
type TriggerDecision struct {
	// ScheduleID identifies the schedule.
	ScheduleID string `json:"schedule_id"`
	// FireAtUnixMs is the nominal fire time in milliseconds since Unix epoch.
	FireAtUnixMs int64 `json:"fire_at_unix_ms"`
	// DispatchAfterMs is the jitter offset in milliseconds to delay actual dispatch.
	DispatchAfterMs int64 `json:"dispatch_after_ms"`
	// IdempotencyKey is a deterministic key for exactly-once dispatch.
	IdempotencyKey string `json:"idempotency_key"`
	// Reason is a human-readable description of why this trigger was generated.
	Reason string `json:"reason"`
}

// Scheduler defines the interface for managing and evaluating schedules.
type Scheduler interface {
	// Register validates and persists a ScheduleSpec. Returns an error if the spec is invalid.
	Register(ctx context.Context, spec ScheduleSpec) error

	// Disable marks a schedule as disabled, preventing future triggers.
	Disable(ctx context.Context, scheduleID string) error

	// ComputeNext returns the next fire time after `after` for the given spec.
	ComputeNext(spec ScheduleSpec, after time.Time) (time.Time, error)

	// Due returns all TriggerDecisions for enabled schedules whose next fire time
	// is at or before `now`. It performs idempotency checking and skips schedules
	// that have already been dispatched for the current slot.
	Due(ctx context.Context, now time.Time) ([]TriggerDecision, error)

	// RecordDispatch persists a TriggerDecision as dispatched.
	RecordDispatch(ctx context.Context, decision TriggerDecision) error
}

// DefaultScheduler implements Scheduler using a ScheduleStore for persistence.
type DefaultScheduler struct {
	store ScheduleStore
}

// NewScheduler creates a DefaultScheduler backed by the given ScheduleStore.
func NewScheduler(store ScheduleStore) *DefaultScheduler {
	return &DefaultScheduler{store: store}
}

// Register validates spec and persists it via the store.
func (s *DefaultScheduler) Register(ctx context.Context, spec ScheduleSpec) error {
	if err := Validate(spec); err != nil {
		return fmt.Errorf("scheduler.Register: %w", err)
	}
	if err := s.store.Put(ctx, spec); err != nil {
		return fmt.Errorf("scheduler.Register: %w", err)
	}
	return nil
}

// Disable fetches the schedule and sets Enabled = false.
func (s *DefaultScheduler) Disable(ctx context.Context, scheduleID string) error {
	spec, err := s.store.Get(ctx, scheduleID)
	if err != nil {
		return fmt.Errorf("scheduler.Disable: %w", err)
	}
	spec.Enabled = false
	if err := s.store.Put(ctx, *spec); err != nil {
		return fmt.Errorf("scheduler.Disable: %w", err)
	}
	return nil
}

// ComputeNext delegates to NextFireTime.
func (s *DefaultScheduler) ComputeNext(spec ScheduleSpec, after time.Time) (time.Time, error) {
	return NextFireTime(spec, after)
}

// Due returns TriggerDecisions for all enabled schedules whose next fire time <= now.
// It uses idempotency keys to skip schedules already dispatched for the current slot.
func (s *DefaultScheduler) Due(ctx context.Context, now time.Time) ([]TriggerDecision, error) {
	specs, err := s.store.ListEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("scheduler.Due: list enabled: %w", err)
	}

	var decisions []TriggerDecision

	for _, spec := range specs {
		// Compute the most recent fire time <= now.
		// Look back far enough to catch any schedule interval. For frequently-firing
		// schedules (e.g., every minute), a small lookback suffices. For infrequent
		// schedules (hourly, daily), we need to search from a wider window.
		// Use 25 hours as the max lookback to cover daily + timezone edge cases.
		lookback := 25 * time.Hour
		candidate, err := NextFireTime(spec, now.Add(-lookback))
		if err != nil {
			// Skip schedules with computation errors (fail-open per schedule, not whole run).
			continue
		}
		// Walk forward to find the most recent fire time <= now.
		for {
			next, nextErr := NextFireTime(spec, candidate)
			if nextErr != nil || next.After(now) {
				break
			}
			candidate = next
		}
		if candidate.After(now) {
			// Not due yet.
			continue
		}

		ikey := idempotencyKey(spec.ScheduleID, candidate)

		dispatched, err := s.store.WasDispatched(ctx, ikey)
		if err != nil {
			return nil, fmt.Errorf("scheduler.Due: idempotency check: %w", err)
		}
		if dispatched {
			continue
		}

		nominalMs := candidate.UnixMilli()
		jitteredTime := ApplyJitter(candidate, spec.JitterWindowMs)
		dispatchAfterMs := jitteredTime.UnixMilli() - nominalMs
		if dispatchAfterMs < 0 {
			dispatchAfterMs = 0
		}

		decisions = append(decisions, TriggerDecision{
			ScheduleID:      spec.ScheduleID,
			FireAtUnixMs:    nominalMs,
			DispatchAfterMs: dispatchAfterMs,
			IdempotencyKey:  ikey,
			Reason:          "scheduled",
		})
	}

	return decisions, nil
}

// RecordDispatch persists the decision via the store.
func (s *DefaultScheduler) RecordDispatch(ctx context.Context, decision TriggerDecision) error {
	firedAt := time.UnixMilli(decision.FireAtUnixMs)
	if err := s.store.RecordDispatch(ctx, decision.ScheduleID, firedAt, decision.IdempotencyKey); err != nil {
		return fmt.Errorf("scheduler.RecordDispatch: %w", err)
	}
	return nil
}

// idempotencyKey returns a deterministic, stable key for (scheduleID, fireTime).
func idempotencyKey(scheduleID string, fireTime time.Time) string {
	raw := fmt.Sprintf("%s:%d", scheduleID, fireTime.UnixMilli())
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
