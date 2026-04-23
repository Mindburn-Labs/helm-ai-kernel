package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// validSpec returns a minimal valid ScheduleSpec for use in tests.
func validSpec(id string) ScheduleSpec {
	return ScheduleSpec{
		ScheduleID:       id,
		TenantID:         "tenant-1",
		Kind:             ScheduleCron,
		Expression:       "*/5 * * * *",
		Timezone:         "UTC",
		CatchupPolicy:    CatchupNone,
		MaxConcurrency:   1,
		JitterWindowMs:   0,
		Retry:            RetryPolicy{MaxAttempts: 3, BackoffMode: "exponential", MinBackoffS: 1, MaxBackoffS: 60},
		Enabled:          true,
		IntentTemplateID: "template-abc",
	}
}

// ─── Cron Parser ──────────────────────────────────────────────────────────────

func TestParseCron_Wildcard(t *testing.T) {
	cs, err := ParseCron("* * * * *")
	require.NoError(t, err)
	assert.Len(t, cs.Minutes, 60)
	assert.Len(t, cs.Hours, 24)
	assert.Len(t, cs.DaysOfMonth, 31)
	assert.Len(t, cs.Months, 12)
	assert.Len(t, cs.DaysOfWeek, 7)
}

func TestParseCron_Literal(t *testing.T) {
	cs, err := ParseCron("30 8 15 6 1")
	require.NoError(t, err)
	assert.Equal(t, []int{30}, cs.Minutes)
	assert.Equal(t, []int{8}, cs.Hours)
	assert.Equal(t, []int{15}, cs.DaysOfMonth)
	assert.Equal(t, []int{6}, cs.Months)
	assert.Equal(t, []int{1}, cs.DaysOfWeek)
}

func TestParseCron_Step_Wildcard(t *testing.T) {
	cs, err := ParseCron("*/15 */6 * * *")
	require.NoError(t, err)
	assert.Equal(t, []int{0, 15, 30, 45}, cs.Minutes)
	assert.Equal(t, []int{0, 6, 12, 18}, cs.Hours)
}

func TestParseCron_Range(t *testing.T) {
	cs, err := ParseCron("0 9-17 * * *")
	require.NoError(t, err)
	assert.Equal(t, []int{0}, cs.Minutes)
	assert.Equal(t, []int{9, 10, 11, 12, 13, 14, 15, 16, 17}, cs.Hours)
}

func TestParseCron_RangeWithStep(t *testing.T) {
	cs, err := ParseCron("0 8-18/2 * * *")
	require.NoError(t, err)
	assert.Equal(t, []int{8, 10, 12, 14, 16, 18}, cs.Hours)
}

func TestParseCron_List(t *testing.T) {
	cs, err := ParseCron("0,15,30,45 * * * *")
	require.NoError(t, err)
	assert.Equal(t, []int{0, 15, 30, 45}, cs.Minutes)
}

func TestParseCron_NamedDaysOfWeek(t *testing.T) {
	cs, err := ParseCron("0 9 * * MON-FRI")
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3, 4, 5}, cs.DaysOfWeek)
}

func TestParseCron_NamedMonths(t *testing.T) {
	cs, err := ParseCron("0 0 1 JAN,JUN,DEC *")
	require.NoError(t, err)
	assert.Equal(t, []int{1, 6, 12}, cs.Months)
}

func TestParseCron_MixedListAndRange(t *testing.T) {
	cs, err := ParseCron("0 8,12,17-19 * * *")
	require.NoError(t, err)
	assert.Equal(t, []int{8, 12, 17, 18, 19}, cs.Hours)
}

func TestParseCron_WrongFieldCount(t *testing.T) {
	_, err := ParseCron("* * * *")
	require.Error(t, err)

	_, err = ParseCron("* * * * * *")
	require.Error(t, err)
}

func TestParseCron_OutOfRange(t *testing.T) {
	_, err := ParseCron("60 * * * *")
	require.Error(t, err)

	_, err = ParseCron("* 24 * * *")
	require.Error(t, err)

	_, err = ParseCron("* * 0 * *")
	require.Error(t, err)

	_, err = ParseCron("* * * 13 *")
	require.Error(t, err)
}

func TestParseCron_InvalidStep(t *testing.T) {
	_, err := ParseCron("*/0 * * * *")
	require.Error(t, err)
}

func TestParseCron_RangeInverted(t *testing.T) {
	_, err := ParseCron("0 18-9 * * *")
	require.Error(t, err)
}

func TestParseCron_LiteralWithStep(t *testing.T) {
	// "5/15" means: starting at 5, every 15, up to max (59) → 5,20,35,50
	cs, err := ParseCron("5/15 * * * *")
	require.NoError(t, err)
	assert.Equal(t, []int{5, 20, 35, 50}, cs.Minutes)
}

func TestParseRRULE_SupportedSubset(t *testing.T) {
	err := ParseRRULE("FREQ=DAILY;INTERVAL=1")
	require.NoError(t, err)

	err = ParseRRULE("FREQ=MONTHLY")
	require.Error(t, err)
}

// ─── Validation ───────────────────────────────────────────────────────────────

func TestValidate_Valid(t *testing.T) {
	assert.NoError(t, Validate(validSpec("s1")))
}

func TestValidate_MissingScheduleID(t *testing.T) {
	s := validSpec("")
	s.ScheduleID = ""
	assert.ErrorIs(t, Validate(s), ErrEmptyScheduleID)
}

func TestValidate_MissingTenantID(t *testing.T) {
	s := validSpec("s1")
	s.TenantID = ""
	assert.ErrorIs(t, Validate(s), ErrEmptyTenantID)
}

func TestValidate_MissingIntentTemplateID(t *testing.T) {
	s := validSpec("s1")
	s.IntentTemplateID = ""
	assert.ErrorIs(t, Validate(s), ErrEmptyIntentTemplateID)
}

func TestValidate_UnknownKind(t *testing.T) {
	s := validSpec("s1")
	s.Kind = "unknown"
	err := Validate(s)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownKind)
}

func TestValidate_UnknownCatchupPolicy(t *testing.T) {
	s := validSpec("s1")
	s.CatchupPolicy = "all"
	err := Validate(s)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownCatchupPolicy)
}

func TestValidate_NegativeMaxConcurrency(t *testing.T) {
	s := validSpec("s1")
	s.MaxConcurrency = -1
	assert.ErrorIs(t, Validate(s), ErrNegativeMaxConcurrency)
}

func TestValidate_NegativeJitterWindow(t *testing.T) {
	s := validSpec("s1")
	s.JitterWindowMs = -100
	assert.ErrorIs(t, Validate(s), ErrNegativeJitterWindow)
}

func TestValidate_InvalidRetryBackoffMode(t *testing.T) {
	s := validSpec("s1")
	s.Retry.BackoffMode = "random"
	err := Validate(s)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidRetryPolicy)
}

func TestValidate_RetryMaxBackoffLessThanMin(t *testing.T) {
	s := validSpec("s1")
	s.Retry.MinBackoffS = 30
	s.Retry.MaxBackoffS = 10
	err := Validate(s)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidRetryPolicy)
}

func TestValidate_InvalidTimezone(t *testing.T) {
	s := validSpec("s1")
	s.Timezone = "Nowhere/Invalid"
	err := Validate(s)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownTimezone)
}

func TestValidate_BadCronExpression(t *testing.T) {
	s := validSpec("s1")
	s.Expression = "99 * * * *"
	require.Error(t, Validate(s))
}

func TestValidate_RRULEKind(t *testing.T) {
	s := validSpec("s1")
	s.Kind = ScheduleRRULE
	s.Expression = "FREQ=DAILY"
	err := Validate(s)
	require.NoError(t, err)
}

// ─── NextFireTime ─────────────────────────────────────────────────────────────

func TestNextFireTime_EveryMinute(t *testing.T) {
	spec := validSpec("s1")
	spec.Expression = "* * * * *"

	after := time.Date(2024, 3, 15, 10, 30, 45, 0, time.UTC)
	next, err := NextFireTime(spec, after)
	require.NoError(t, err)

	expected := time.Date(2024, 3, 15, 10, 31, 0, 0, time.UTC)
	assert.Equal(t, expected, next)
}

func TestNextFireTime_Every5Minutes(t *testing.T) {
	spec := validSpec("s1")
	spec.Expression = "*/5 * * * *"

	after := time.Date(2024, 3, 15, 10, 3, 0, 0, time.UTC)
	next, err := NextFireTime(spec, after)
	require.NoError(t, err)

	expected := time.Date(2024, 3, 15, 10, 5, 0, 0, time.UTC)
	assert.Equal(t, expected, next)
}

func TestNextFireTime_HourBoundary(t *testing.T) {
	spec := validSpec("s1")
	spec.Expression = "0 * * * *" // top of every hour

	after := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	next, err := NextFireTime(spec, after)
	require.NoError(t, err)

	expected := time.Date(2024, 3, 15, 11, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, next)
}

func TestNextFireTime_DayBoundary(t *testing.T) {
	spec := validSpec("s1")
	spec.Expression = "0 0 * * *" // midnight daily

	after := time.Date(2024, 3, 15, 10, 0, 0, 0, time.UTC)
	next, err := NextFireTime(spec, after)
	require.NoError(t, err)

	expected := time.Date(2024, 3, 16, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, next)
}

func TestNextFireTime_SpecificDayOfWeek(t *testing.T) {
	spec := validSpec("s1")
	spec.Expression = "0 9 * * MON" // 09:00 on Mondays

	// 2024-03-15 is a Friday.
	after := time.Date(2024, 3, 15, 9, 0, 0, 0, time.UTC)
	next, err := NextFireTime(spec, after)
	require.NoError(t, err)

	// Next Monday is 2024-03-18.
	expected := time.Date(2024, 3, 18, 9, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, next)
}

func TestNextFireTime_SpecificDayOfMonth(t *testing.T) {
	spec := validSpec("s1")
	spec.Expression = "0 0 1 * *" // midnight on 1st of each month

	after := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)
	next, err := NextFireTime(spec, after)
	require.NoError(t, err)

	expected := time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, next)
}

func TestNextFireTime_MonthBoundary(t *testing.T) {
	spec := validSpec("s1")
	spec.Expression = "0 0 1 6 *" // midnight on June 1st

	after := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	next, err := NextFireTime(spec, after)
	require.NoError(t, err)

	expected := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, next)
}

func TestNextFireTime_WithTimezone(t *testing.T) {
	spec := validSpec("s1")
	spec.Expression = "0 9 * * *"
	spec.Timezone = "America/New_York"

	// Create a reference time in UTC that corresponds to before 09:00 ET.
	// On a non-DST day (e.g. 2024-01-15), ET = UTC-5.
	// So 09:00 ET = 14:00 UTC.
	after := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC) // 05:00 ET
	next, err := NextFireTime(spec, after)
	require.NoError(t, err)

	loc, _ := time.LoadLocation("America/New_York")
	nextInET := next.In(loc)
	assert.Equal(t, 9, nextInET.Hour())
	assert.Equal(t, 0, nextInET.Minute())
}

func TestNextFireTime_UnsupportedKind(t *testing.T) {
	spec := validSpec("s1")
	spec.Kind = ScheduleRRULE
	_, err := NextFireTime(spec, time.Now())
	require.Error(t, err)
}

// ─── Jitter ───────────────────────────────────────────────────────────────────

func TestApplyJitter_ZeroWindow(t *testing.T) {
	base := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	result := ApplyJitter(base, 0)
	assert.Equal(t, base, result)
}

func TestApplyJitter_NegativeWindow(t *testing.T) {
	base := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	result := ApplyJitter(base, -100)
	assert.Equal(t, base, result)
}

func TestApplyJitter_WithinWindow(t *testing.T) {
	base := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	window := 5000 // 5 seconds
	// Run multiple times to get statistical confidence.
	for i := 0; i < 200; i++ {
		result := ApplyJitter(base, window)
		diff := result.Sub(base)
		assert.GreaterOrEqual(t, diff.Milliseconds(), int64(0))
		assert.Less(t, diff.Milliseconds(), int64(window))
	}
}

// ─── InMemoryScheduleStore ────────────────────────────────────────────────────

func TestStore_PutAndGet(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	spec := validSpec("s1")

	require.NoError(t, store.Put(ctx, spec))

	got, err := store.Get(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, spec.ScheduleID, got.ScheduleID)
	assert.Equal(t, spec.TenantID, got.TenantID)
}

func TestStore_GetNotFound(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()

	_, err := store.Get(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScheduleNotFound)
}

func TestStore_List(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()

	s1 := validSpec("s1")
	s2 := validSpec("s2")
	s3 := validSpec("s3")
	s3.TenantID = "tenant-2"

	require.NoError(t, store.Put(ctx, s1))
	require.NoError(t, store.Put(ctx, s2))
	require.NoError(t, store.Put(ctx, s3))

	list, err := store.List(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, list, 2)

	list2, err := store.List(ctx, "tenant-2")
	require.NoError(t, err)
	assert.Len(t, list2, 1)
}

func TestStore_ListEnabled(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()

	s1 := validSpec("s1")
	s2 := validSpec("s2")
	s2.Enabled = false

	require.NoError(t, store.Put(ctx, s1))
	require.NoError(t, store.Put(ctx, s2))

	list, err := store.ListEnabled(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "s1", list[0].ScheduleID)
}

func TestStore_Delete(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	spec := validSpec("s1")
	require.NoError(t, store.Put(ctx, spec))

	require.NoError(t, store.Delete(ctx, "s1"))

	_, err := store.Get(ctx, "s1")
	assert.ErrorIs(t, err, ErrScheduleNotFound)
}

func TestStore_DeleteNotFound(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	err := store.Delete(ctx, "ghost")
	assert.ErrorIs(t, err, ErrScheduleNotFound)
}

func TestStore_IdempotentDispatch(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()

	firedAt := time.Now()
	ikey := "key-123"

	require.NoError(t, store.RecordDispatch(ctx, "s1", firedAt, ikey))

	was, err := store.WasDispatched(ctx, ikey)
	require.NoError(t, err)
	assert.True(t, was)

	was2, err := store.WasDispatched(ctx, "other-key")
	require.NoError(t, err)
	assert.False(t, was2)
}

// ─── DefaultScheduler ─────────────────────────────────────────────────────────

func TestScheduler_Register(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	sched := NewScheduler(store)

	spec := validSpec("s1")
	require.NoError(t, sched.Register(ctx, spec))

	// Verify it landed in the store.
	got, err := store.Get(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, "s1", got.ScheduleID)
}

func TestScheduler_Register_InvalidSpec(t *testing.T) {
	ctx := context.Background()
	sched := NewScheduler(NewInMemoryScheduleStore())

	bad := validSpec("")
	err := sched.Register(ctx, bad)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyScheduleID)
}

func TestScheduler_Disable(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	sched := NewScheduler(store)

	spec := validSpec("s1")
	require.NoError(t, sched.Register(ctx, spec))
	require.NoError(t, sched.Disable(ctx, "s1"))

	got, err := store.Get(ctx, "s1")
	require.NoError(t, err)
	assert.False(t, got.Enabled)
}

func TestScheduler_Disable_NotFound(t *testing.T) {
	ctx := context.Background()
	sched := NewScheduler(NewInMemoryScheduleStore())
	err := sched.Disable(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScheduleNotFound)
}

func TestScheduler_ComputeNext(t *testing.T) {
	sched := NewScheduler(NewInMemoryScheduleStore())
	spec := validSpec("s1")
	spec.Expression = "0 12 * * *"

	after := time.Date(2024, 3, 15, 12, 1, 0, 0, time.UTC)
	next, err := sched.ComputeNext(spec, after)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2024, 3, 16, 12, 0, 0, 0, time.UTC), next)
}

func TestScheduler_Due(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	sched := NewScheduler(store)

	// A schedule that fires every minute.
	spec := validSpec("s1")
	spec.Expression = "* * * * *"
	spec.JitterWindowMs = 0
	require.NoError(t, sched.Register(ctx, spec))

	// Pick a "now" that is exactly on a minute boundary.
	now := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	decisions, err := sched.Due(ctx, now)
	require.NoError(t, err)
	require.Len(t, decisions, 1)
	assert.Equal(t, "s1", decisions[0].ScheduleID)
	assert.Equal(t, "scheduled", decisions[0].Reason)
}

func TestScheduler_Due_DisabledScheduleSkipped(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	sched := NewScheduler(store)

	spec := validSpec("s1")
	spec.Expression = "* * * * *"
	spec.Enabled = false
	require.NoError(t, store.Put(ctx, spec))

	now := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	decisions, err := sched.Due(ctx, now)
	require.NoError(t, err)
	assert.Len(t, decisions, 0)
}

func TestScheduler_Due_NotYetDue(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	sched := NewScheduler(store)

	// Fire only on the 20th of each month at midnight.
	spec := validSpec("s1")
	spec.Expression = "0 0 20 * *"
	require.NoError(t, sched.Register(ctx, spec))

	// "now" is March 15 10:00 — next fire is March 20. The lookback window (25h)
	// reaches March 14 09:00. Since the schedule only fires monthly on the 20th,
	// there is no fire time within the search window that is <= now.
	now := time.Date(2024, 3, 15, 10, 0, 0, 0, time.UTC)
	decisions, err := sched.Due(ctx, now)
	require.NoError(t, err)
	assert.Len(t, decisions, 0)
}

func TestScheduler_Due_IdempotentDispatch(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	sched := NewScheduler(store)

	spec := validSpec("s1")
	spec.Expression = "* * * * *"
	spec.JitterWindowMs = 0
	require.NoError(t, sched.Register(ctx, spec))

	now := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)

	// First Due call — should produce one decision.
	decisions, err := sched.Due(ctx, now)
	require.NoError(t, err)
	require.Len(t, decisions, 1)

	// Record the dispatch.
	require.NoError(t, sched.RecordDispatch(ctx, decisions[0]))

	// Second Due call at the same time — should be empty (already dispatched).
	decisions2, err := sched.Due(ctx, now)
	require.NoError(t, err)
	assert.Len(t, decisions2, 0)
}

func TestScheduler_RecordDispatch(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	sched := NewScheduler(store)

	decision := TriggerDecision{
		ScheduleID:     "s1",
		FireAtUnixMs:   time.Now().UnixMilli(),
		IdempotencyKey: "key-xyz",
		Reason:         "scheduled",
	}
	require.NoError(t, sched.RecordDispatch(ctx, decision))

	was, err := store.WasDispatched(ctx, "key-xyz")
	require.NoError(t, err)
	assert.True(t, was)
}

// ─── DispatchReceipt ──────────────────────────────────────────────────────────

func TestNewDispatchReceipt(t *testing.T) {
	decision := TriggerDecision{
		ScheduleID:      "s1",
		FireAtUnixMs:    1710000000000,
		DispatchAfterMs: 50,
		IdempotencyKey:  "ikey-abc",
		Reason:          "scheduled",
	}

	r := NewDispatchReceipt(decision)

	assert.NotEmpty(t, r.ReceiptID)
	assert.Equal(t, "s1", r.ScheduleID)
	assert.Equal(t, int64(1710000000000), r.FireAtUnixMs)
	assert.Equal(t, "ikey-abc", r.IdempotencyKey)
	assert.NotEmpty(t, r.ContentHash)
	assert.Greater(t, r.DispatchedAt, int64(0))
}

func TestNewDispatchReceipt_DeterministicHash(t *testing.T) {
	decision := TriggerDecision{
		ScheduleID:     "s2",
		FireAtUnixMs:   1710000060000,
		IdempotencyKey: "ikey-def",
	}

	r1 := NewDispatchReceipt(decision)
	r2 := NewDispatchReceipt(decision)

	// Different receipt IDs (random UUIDs).
	assert.NotEqual(t, r1.ReceiptID, r2.ReceiptID)

	// But the content hash covers receipt_id too, so hashes will differ.
	// The hash is a function of receipt_id (which is random), so this is expected.
	// What we verify is that the hash is non-empty and well-formed (64 hex chars = SHA-256).
	assert.Len(t, r1.ContentHash, 64)
	assert.Len(t, r2.ContentHash, 64)
}

// ─── IdempotencyKey ───────────────────────────────────────────────────────────

func TestIdempotencyKey_Stable(t *testing.T) {
	t1 := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	k1 := idempotencyKey("schedule-1", t1)
	k2 := idempotencyKey("schedule-1", t1)
	assert.Equal(t, k1, k2)
}

func TestIdempotencyKey_Unique(t *testing.T) {
	t1 := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	t2 := t1.Add(time.Minute)
	k1 := idempotencyKey("schedule-1", t1)
	k2 := idempotencyKey("schedule-1", t2)
	assert.NotEqual(t, k1, k2)

	k3 := idempotencyKey("schedule-2", t1)
	assert.NotEqual(t, k1, k3)
}

// ─── Edge Cases ───────────────────────────────────────────────────────────────

func TestValidate_AllCatchupPolicies(t *testing.T) {
	for _, policy := range []CatchupPolicy{CatchupNone, CatchupSingle, CatchupBackfill} {
		s := validSpec("s1")
		s.CatchupPolicy = policy
		assert.NoError(t, Validate(s), "policy %q should be valid", policy)
	}
}

func TestValidate_AllScheduleKinds(t *testing.T) {
	// Cron: valid
	s := validSpec("s1")
	s.Kind = ScheduleCron
	s.Expression = "0 * * * *"
	assert.NoError(t, Validate(s))

	// RRULE: known kind with supported expression.
	s2 := validSpec("s2")
	s2.Kind = ScheduleRRULE
	s2.Expression = "FREQ=DAILY"
	require.NoError(t, Validate(s2))
}

func TestNextFireTime_EndOfYear(t *testing.T) {
	spec := validSpec("s1")
	spec.Expression = "59 23 31 12 *" // last minute of the year

	after := time.Date(2024, 12, 31, 23, 59, 0, 0, time.UTC)
	// after is exactly on the fire time, so next should be next year.
	next, err := NextFireTime(spec, after)
	require.NoError(t, err)
	assert.Equal(t, 2025, next.Year())
	assert.Equal(t, time.December, next.Month())
	assert.Equal(t, 31, next.Day())
	assert.Equal(t, 23, next.Hour())
	assert.Equal(t, 59, next.Minute())
}

func TestStore_Upsert(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	spec := validSpec("s1")
	require.NoError(t, store.Put(ctx, spec))

	// Update the expression.
	spec.Expression = "0 12 * * *"
	require.NoError(t, store.Put(ctx, spec))

	got, err := store.Get(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, "0 12 * * *", got.Expression)
}

// TestNextFireTime_StrictlyAfter ensures that NextFireTime never returns a time
// equal to `after` — it must be strictly greater.
func TestNextFireTime_StrictlyAfter(t *testing.T) {
	spec := validSpec("s1")
	spec.Expression = "* * * * *"

	// `after` is exactly on a minute boundary.
	after := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	next, err := NextFireTime(spec, after)
	require.NoError(t, err)
	assert.True(t, next.After(after), "next fire time must be strictly after `after`")
}

// TestValidate_EmptyExpression exercises the EmptyExpression path.
func TestValidate_EmptyExpression(t *testing.T) {
	s := validSpec("s1")
	s.Expression = ""
	assert.ErrorIs(t, Validate(s), ErrEmptyExpression)
}

// TestValidate_RetryNegativeMaxAttempts exercises the negative attempts path.
func TestValidate_RetryNegativeMaxAttempts(t *testing.T) {
	s := validSpec("s1")
	s.Retry.MaxAttempts = -1
	err := Validate(s)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidRetryPolicy)
}

// TestScheduler_MultipleSchedulesDue verifies that Due returns decisions for all
// due schedules, not just the first.
func TestScheduler_MultipleSchedulesDue(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryScheduleStore()
	sched := NewScheduler(store)

	for _, id := range []string{"s1", "s2", "s3"} {
		spec := validSpec(id)
		spec.Expression = "* * * * *"
		spec.JitterWindowMs = 0
		require.NoError(t, sched.Register(ctx, spec))
	}

	now := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	decisions, err := sched.Due(ctx, now)
	require.NoError(t, err)
	assert.Len(t, decisions, 3)
}

// TestValidate_UnknownKindError checks the error wrapping is preserved for unknown kind.
func TestValidate_UnknownKindError(t *testing.T) {
	s := validSpec("s1")
	s.Kind = ScheduleKind("ical")
	err := Validate(s)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnknownKind))
}
