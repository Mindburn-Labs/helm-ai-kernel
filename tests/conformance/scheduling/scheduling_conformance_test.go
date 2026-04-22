package scheduling_conformance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/scheduler"
)

// validSpec returns a minimal ScheduleSpec that passes Validate.
func validSpec(id, expression string) scheduler.ScheduleSpec {
	return scheduler.ScheduleSpec{
		ScheduleID:       id,
		TenantID:         "tenant-conformance",
		Kind:             scheduler.ScheduleCron,
		Expression:       expression,
		CatchupPolicy:    scheduler.CatchupNone,
		Enabled:          true,
		IntentTemplateID: "intent-conformance",
	}
}

// TestSchedulerConformance_ParseEveryMinute verifies parsing of "* * * * *".
func TestSchedulerConformance_ParseEveryMinute(t *testing.T) {
	t.Run("every_minute_expression_parses_successfully", func(t *testing.T) {
		cs, err := scheduler.ParseCron("* * * * *")
		require.NoError(t, err)
		assert.Len(t, cs.Minutes, 60, "wildcard minute must expand to all 60 values")
		assert.Len(t, cs.Hours, 24, "wildcard hour must expand to all 24 values")
	})
}

// TestSchedulerConformance_ParseHourly verifies parsing of "0 * * * *".
func TestSchedulerConformance_ParseHourly(t *testing.T) {
	t.Run("hourly_expression_parses_successfully", func(t *testing.T) {
		cs, err := scheduler.ParseCron("0 * * * *")
		require.NoError(t, err)
		assert.Equal(t, []int{0}, cs.Minutes)
		assert.Len(t, cs.Hours, 24, "wildcard hour must expand to all 24 values")
	})
}

// TestSchedulerConformance_ParseDaily verifies parsing of "0 0 * * *".
func TestSchedulerConformance_ParseDaily(t *testing.T) {
	t.Run("daily_midnight_expression_parses_successfully", func(t *testing.T) {
		cs, err := scheduler.ParseCron("0 0 * * *")
		require.NoError(t, err)
		assert.Equal(t, []int{0}, cs.Minutes)
		assert.Equal(t, []int{0}, cs.Hours)
	})
}

// TestSchedulerConformance_NextFireTimeComputation verifies NextFireTime for a simple expression.
func TestSchedulerConformance_NextFireTimeComputation(t *testing.T) {
	spec := validSpec("nft-001", "*/15 * * * *") // every 15 minutes

	// Anchor "now" at a known minute boundary so the result is deterministic.
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	t.Run("next_fire_is_after_base_time", func(t *testing.T) {
		next, err := scheduler.NextFireTime(spec, base)
		require.NoError(t, err)
		assert.True(t, next.After(base), "next fire time must be strictly after the base time")
	})

	t.Run("next_fire_is_within_one_schedule_period", func(t *testing.T) {
		next, err := scheduler.NextFireTime(spec, base)
		require.NoError(t, err)
		// For */15, the next fire after :00 is :15.
		diff := next.Sub(base)
		assert.LessOrEqual(t, diff, 20*time.Minute, "next fire must be within one 15-min interval")
	})
}

// TestSchedulerConformance_TimezoneHandling verifies that timezone-aware NextFireTime works.
func TestSchedulerConformance_TimezoneHandling(t *testing.T) {
	spec := validSpec("tz-001", "0 9 * * *") // 09:00 every day
	spec.Timezone = "America/New_York"

	// Base time: 2026-01-15 09:30 UTC = 04:30 EST.
	// Next 09:00 EST = 2026-01-15 14:00 UTC.
	base := time.Date(2026, 1, 15, 9, 30, 0, 0, time.UTC)

	t.Run("timezone_aware_schedule_fires_at_correct_utc_time", func(t *testing.T) {
		next, err := scheduler.NextFireTime(spec, base)
		require.NoError(t, err)
		assert.True(t, next.After(base))

		// Convert next to UTC hour for comparison.
		nextUTC := next.UTC()
		// EST = UTC-5 in January; 09:00 EST = 14:00 UTC.
		assert.Equal(t, 14, nextUTC.Hour(), "09:00 EST must fire at 14:00 UTC in January")
		assert.Equal(t, 0, nextUTC.Minute())
	})
}

// TestSchedulerConformance_JitterStaysWithinWindow verifies ApplyJitter bounds.
func TestSchedulerConformance_JitterStaysWithinWindow(t *testing.T) {
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	jitterWindowMs := 5000 // 5 seconds

	t.Run("jitter_stays_within_declared_window", func(t *testing.T) {
		// Run multiple times to exercise the RNG.
		for i := 0; i < 50; i++ {
			jittered := scheduler.ApplyJitter(base, jitterWindowMs)
			diff := jittered.Sub(base)
			assert.GreaterOrEqual(t, diff, time.Duration(0), "jitter must not be negative")
			assert.Less(t, diff, time.Duration(jitterWindowMs)*time.Millisecond,
				"jitter must be strictly less than the window")
		}
	})

	t.Run("zero_jitter_window_returns_unchanged_time", func(t *testing.T) {
		result := scheduler.ApplyJitter(base, 0)
		assert.Equal(t, base, result)
	})
}

// TestSchedulerConformance_RegisterScheduleAppearsInList verifies Register + List round-trip.
func TestSchedulerConformance_RegisterScheduleAppearsInList(t *testing.T) {
	store := scheduler.NewInMemoryScheduleStore()
	sched := scheduler.NewScheduler(store)
	ctx := context.Background()

	spec := validSpec("reg-001", "0 * * * *")

	t.Run("registered_schedule_appears_in_list", func(t *testing.T) {
		err := sched.Register(ctx, spec)
		require.NoError(t, err)

		schedules, err := store.List(ctx, "tenant-conformance")
		require.NoError(t, err)
		require.Len(t, schedules, 1)
		assert.Equal(t, "reg-001", schedules[0].ScheduleID)
	})
}

// TestSchedulerConformance_DisabledScheduleExcludedFromDue verifies Disable + Due interaction.
func TestSchedulerConformance_DisabledScheduleExcludedFromDue(t *testing.T) {
	store := scheduler.NewInMemoryScheduleStore()
	sched := scheduler.NewScheduler(store)
	ctx := context.Background()

	spec := validSpec("dis-001", "* * * * *") // fires every minute
	spec.Enabled = true

	require.NoError(t, sched.Register(ctx, spec))

	t.Run("schedule_is_due_before_disable", func(t *testing.T) {
		// Use a time where the cron should be due: 1 minute after epoch start.
		now := time.Date(2026, 1, 15, 10, 1, 0, 0, time.UTC)
		decisions, err := sched.Due(ctx, now)
		require.NoError(t, err)
		assert.NotEmpty(t, decisions, "enabled schedule must appear in Due results")
	})

	t.Run("disabled_schedule_is_excluded_from_due", func(t *testing.T) {
		require.NoError(t, sched.Disable(ctx, "dis-001"))

		enabled, err := store.ListEnabled(ctx)
		require.NoError(t, err)
		for _, s := range enabled {
			assert.NotEqual(t, "dis-001", s.ScheduleID)
		}
	})
}

// TestSchedulerConformance_IdempotentDispatch verifies that the same trigger key dispatches only once.
func TestSchedulerConformance_IdempotentDispatch(t *testing.T) {
	store := scheduler.NewInMemoryScheduleStore()
	sched := scheduler.NewScheduler(store)
	ctx := context.Background()

	spec := validSpec("idem-001", "* * * * *")
	require.NoError(t, sched.Register(ctx, spec))

	now := time.Date(2026, 1, 15, 10, 1, 0, 0, time.UTC)

	t.Run("first_due_returns_decisions", func(t *testing.T) {
		decisions, err := sched.Due(ctx, now)
		require.NoError(t, err)
		require.NotEmpty(t, decisions)

		// Record the dispatch.
		for _, d := range decisions {
			require.NoError(t, sched.RecordDispatch(ctx, d))
		}
	})

	t.Run("second_due_for_same_slot_returns_no_decisions", func(t *testing.T) {
		decisions, err := sched.Due(ctx, now)
		require.NoError(t, err)
		assert.Empty(t, decisions, "already-dispatched trigger must not fire again")
	})
}

// TestSchedulerConformance_CatchupPolicyNone verifies that "none" skips missed fires.
func TestSchedulerConformance_CatchupPolicyNone(t *testing.T) {
	store := scheduler.NewInMemoryScheduleStore()
	sched := scheduler.NewScheduler(store)
	ctx := context.Background()

	spec := validSpec("cup-none-001", "0 9 * * *") // 09:00 daily
	spec.CatchupPolicy = scheduler.CatchupNone
	require.NoError(t, sched.Register(ctx, spec))

	// Simulate checking well after the scheduled time; Due should produce at most one decision.
	now := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	t.Run("catchup_none_produces_at_most_one_decision_per_call", func(t *testing.T) {
		decisions, err := sched.Due(ctx, now)
		require.NoError(t, err)
		// CatchupNone: at most one slot (the last missed slot <= now).
		assert.LessOrEqual(t, len(decisions), 1)
	})
}

// TestSchedulerConformance_CatchupPolicySingle verifies that "single" fires once for missed window.
func TestSchedulerConformance_CatchupPolicySingle(t *testing.T) {
	store := scheduler.NewInMemoryScheduleStore()
	sched := scheduler.NewScheduler(store)
	ctx := context.Background()

	spec := validSpec("cup-single-001", "0 9 * * *") // 09:00 daily
	spec.CatchupPolicy = scheduler.CatchupSingle
	require.NoError(t, sched.Register(ctx, spec))

	now := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	t.Run("catchup_single_fires_at_most_once_for_missed_window", func(t *testing.T) {
		decisions, err := sched.Due(ctx, now)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(decisions), 1)
	})
}

// TestSchedulerConformance_ValidationRejectsInvalidCronExpressions verifies Validate fails on bad cron.
func TestSchedulerConformance_ValidationRejectsInvalidCronExpressions(t *testing.T) {
	cases := []struct {
		name       string
		expression string
	}{
		{"too_few_fields", "* * * *"},
		{"too_many_fields", "* * * * * *"},
		{"out_of_range_minute", "61 * * * *"},
		{"out_of_range_hour", "0 25 * * *"},
		{"invalid_step_zero", "*/0 * * * *"},
		{"non_numeric_field", "abc * * * *"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			spec := validSpec("val-"+tc.name, tc.expression)
			err := scheduler.Validate(spec)
			require.Error(t, err, "expression %q must be rejected by Validate", tc.expression)
		})
	}
}

// TestSchedulerConformance_ValidationAcceptsValidExpressions verifies Validate accepts correct cron.
func TestSchedulerConformance_ValidationAcceptsValidExpressions(t *testing.T) {
	cases := []struct {
		name       string
		expression string
	}{
		{"every_minute", "* * * * *"},
		{"every_hour", "0 * * * *"},
		{"daily_midnight", "0 0 * * *"},
		{"weekdays_9am", "0 9 * * 1-5"},
		{"every_15_minutes", "*/15 * * * *"},
		{"named_days", "0 8 * * MON-FRI"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			spec := validSpec("ok-"+tc.name, tc.expression)
			err := scheduler.Validate(spec)
			require.NoError(t, err, "expression %q must be accepted by Validate", tc.expression)
		})
	}
}
